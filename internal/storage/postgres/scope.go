// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// scope.go — the self-hosted engine's scope-registry + scan-audit
// repository (v0.3.2).  The scope registry was DEFERRED data until now
// (migration 0006 created it; nothing wrote it): this file is the first
// writer, implementing exactly the observe gateway's and the `gseer
// scope` CLI's contract — create / list / get / revoke + the append-only
// decision log.
//
// Write validation is fail-closed and shared by shape with the sqlite
// engine: kind must be one of the four supported kinds, the value must
// pass the suppress package's canonicalizers (so scope matching can
// never diverge from suppression matching), protocols/ports must be
// non-empty explicit lists (default-deny by construction), and the
// execution limits must be sane.

// ErrScopeExists — a create hit the (kind, value) uniqueness constraint.
var ErrScopeExists = storage.ErrScopeExists

// validateScopeForWrite canonicalizes sc.Value per kind and validates
// the explicit-permission lists.  Mutates sc in place (value becomes
// canonical).
func validateScopeForWrite(sc *storage.Scope) error {
	if sc == nil {
		return fmt.Errorf("E_DB_USAGE: scope is nil")
	}
	var err error
	switch sc.Kind {
	case storage.ScopeKindDomain, storage.ScopeKindDomainSuffix:
		var canonical string
		canonical, err = suppress.NormalizeDomain(sc.Value)
		if err == nil && sc.Kind == storage.ScopeKindDomainSuffix {
			// NormalizeDomain strips the trailing dot; a suffix keeps the
			// "*.example.com"-free bare form ("example.com") — matching is
			// name==suffix or name endswith "."+suffix.
			canonical = stringsSuffixTrim(canonical)
		}
		sc.Value = canonical
	case storage.ScopeKindIP:
		sc.Value, err = suppress.NormalizeIP(sc.Value)
	case storage.ScopeKindCIDR:
		sc.Value, err = suppress.NormalizeCIDR(sc.Value)
	default:
		return fmt.Errorf("E_DB_USAGE: invalid scope kind %q (want domain | domain_suffix | cidr | ip)", sc.Kind)
	}
	if err != nil {
		return fmt.Errorf("E_DB_USAGE: scope value failed normalization: %w", err)
	}
	if sc.Value == "" {
		return fmt.Errorf("E_DB_USAGE: scope value is empty")
	}
	protos, perr := storage.ParseScopeProtocols(sc.Protocols)
	if perr != nil {
		return fmt.Errorf("E_DB_USAGE: scope protocols: %w", perr)
	}
	if len(protos) == 0 {
		return fmt.Errorf("E_DB_USAGE: scope permits no protocol — an explicit list (http and/or tls) is required; default-deny is expressed by NOT having a scope, not by an empty one")
	}
	sc.Protocols = protos
	ports, lerr := storage.ParseScopePorts(sc.Ports)
	if lerr != nil {
		return fmt.Errorf("E_DB_USAGE: scope ports: %w", lerr)
	}
	if len(ports) == 0 {
		return fmt.Errorf("E_DB_USAGE: scope permits no port — an explicit list is required; default-deny is expressed by NOT having a scope, not by an empty one")
	}
	sc.Ports = ports
	if sc.Mode == "" {
		sc.Mode = "allow"
	}
	if sc.Mode != "allow" && sc.Mode != "deny" {
		return fmt.Errorf("E_DB_USAGE: invalid scope mode %q (want allow | deny)", sc.Mode)
	}
	if sc.MaxConcurrency < 1 {
		sc.MaxConcurrency = 1
	}
	if sc.MaxRequests < 1 {
		sc.MaxRequests = 1
	}
	if sc.MaxTotalBytes < 0 {
		sc.MaxTotalBytes = 0
	}
	if sc.CreatedAt.IsZero() {
		sc.CreatedAt = time.Now().UTC()
	}
	return nil
}

// stringsSuffixTrim drops a leading "*." if the operator wrote the
// wildcard spelling for a suffix scope (the bare form is canonical).
func stringsSuffixTrim(s string) string {
	if len(s) > 2 && s[:2] == "*." {
		return s[2:]
	}
	return s
}

const insertScopeSQL = `INSERT INTO scopes
    (kind, value, mode, note, protocols, ports, expires_at, revoked_at,
     max_concurrency, max_requests, max_total_bytes, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id`

const scopeColumns = `id, kind, value, mode, note, protocols, ports,
    expires_at, revoked_at, max_concurrency, max_requests, max_total_bytes, created_at`

// scanScopeRow maps one scopes row into the canonical type.
func scanScopeRow(row pgx.Row) (storage.Scope, error) {
	var (
		sc      storage.Scope
		protos  []string
		ports   []int
		revoked *time.Time
		expires *time.Time
	)
	if err := row.Scan(&sc.ID, &sc.Kind, &sc.Value, &sc.Mode, &sc.Note,
		&protos, &ports, &expires, &revoked,
		&sc.MaxConcurrency, &sc.MaxRequests, &sc.MaxTotalBytes, &sc.CreatedAt); err != nil {
		return storage.Scope{}, err
	}
	sc.Protocols, sc.Ports = protos, ports
	sc.RevokedAt, sc.ExpiresAt = revoked, expires
	return sc, nil
}

// CreateScope inserts one scope (unique per (kind, value)).
func (s *Store) CreateScope(ctx context.Context, sc *storage.Scope) (int64, error) {
	if err := validateScopeForWrite(sc); err != nil {
		return 0, err
	}
	if sc.ExpiresAt != nil {
		t := sc.ExpiresAt.UTC()
		sc.ExpiresAt = &t
	}
	var id int64
	err := s.pool.QueryRow(ctx, insertScopeSQL,
		string(sc.Kind), sc.Value, sc.Mode, sc.Note,
		sc.Protocols, sc.Ports, sc.ExpiresAt, sc.RevokedAt,
		sc.MaxConcurrency, sc.MaxRequests, sc.MaxTotalBytes, sc.CreatedAt.UTC(),
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return 0, fmt.Errorf("E_SCOPE_EXISTS: a %s scope for %q already exists (id lookup: gseer scope list) — revoke it and create a replacement, or use the existing scope: %w",
				sc.Kind, sc.Value, ErrScopeExists)
		}
		return 0, fmt.Errorf("cannot create scope: %w", err)
	}
	sc.ID = id
	return id, nil
}

// GetScope resolves one scope by id.
func (s *Store) GetScope(ctx context.Context, id int64) (storage.Scope, error) {
	sc, err := scanScopeRow(s.pool.QueryRow(ctx,
		`SELECT `+scopeColumns+` FROM scopes WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return storage.Scope{}, storage.ErrScopeNotFound
	}
	return sc, err
}

// ListScopes returns every scope (active, expired and revoked — the
// registry keeps its history; Active(now) separates the live ones).
func (s *Store) ListScopes(ctx context.Context) ([]storage.Scope, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scopeColumns+` FROM scopes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("cannot list scopes: %w", err)
	}
	defer rows.Close()
	var out []storage.Scope
	for rows.Next() {
		sc, serr := scanScopeRow(rows)
		if serr != nil {
			return nil, fmt.Errorf("cannot list scopes: %w", serr)
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot list scopes: %w", err)
	}
	return out, nil
}

// RevokeScope marks one scope revoked (UPDATE revoked_at; the row stays
// as history).  Returns whether a live row was revoked (false when the
// scope was already revoked or does not exist).
func (s *Store) RevokeScope(ctx context.Context, id int64, when time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE scopes SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`,
		id, when.UTC())
	if err != nil {
		return false, fmt.Errorf("cannot revoke scope %d: %w", id, err)
	}
	return tag.RowsAffected() > 0, nil
}

// InsertScanAudit appends one gateway decision to scan_audits.
func (s *Store) InsertScanAudit(ctx context.Context, rec *storage.ScanAudit) error {
	if rec.TS.IsZero() {
		rec.TS = time.Now().UTC()
	}
	detail := []byte("{}")
	if rec.Detail != nil {
		b, err := json.Marshal(rec.Detail)
		if err != nil {
			return fmt.Errorf("E_DB_USAGE: scan audit detail not JSON-serializable: %w", err)
		}
		detail = b
	}
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO scan_audits
        (ts, target_host, target_ip, port, protocol, decision, reason, scope_id, detail)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		rec.TS.UTC(), rec.TargetHost, rec.TargetIP, rec.Port, rec.Protocol,
		rec.Decision, rec.Reason, rec.ScopeID, detail,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("cannot record scan audit: %w", err)
	}
	rec.ID = id
	return nil
}

// ListScanAudits returns the most recent audit rows (limit 0 = 100).
func (s *Store) ListScanAudits(ctx context.Context, limit int) ([]storage.ScanAudit, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, ts, target_host, target_ip, port,
        protocol, decision, reason, scope_id, detail
        FROM scan_audits ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cannot list scan audits: %w", err)
	}
	defer rows.Close()
	var out []storage.ScanAudit
	for rows.Next() {
		var (
			rec    storage.ScanAudit
			detail []byte
		)
		if err := rows.Scan(&rec.ID, &rec.TS, &rec.TargetHost, &rec.TargetIP,
			&rec.Port, &rec.Protocol, &rec.Decision, &rec.Reason, &rec.ScopeID, &detail); err != nil {
			return nil, fmt.Errorf("cannot list scan audits: %w", err)
		}
		if len(detail) > 0 && string(detail) != "{}" {
			_ = json.Unmarshal(detail, &rec.Detail)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
