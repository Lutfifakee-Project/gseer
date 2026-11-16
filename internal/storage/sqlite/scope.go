// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// scope.go — the personal engine's scope-registry + scan-audit
// repository: the exact PG contract (same canonical storage.Scope /
// storage.ScanAudit types, same validation via the SHARED
// validateScopeForWrite semantics), lowered to database/sql + the
// personal dialect (CSV protocol/port lists, fixed-width UTC text
// timestamps).
//
// Personal mode had NO scopes table before migration
// 0002_active_observation — parity with the PostgreSQL engine is now
// complete for the active-observation surface.

// ErrScopeNotFound / ErrScopeExists alias the storage-level sentinels
// (the same vocabulary every other sqlite collection error uses).
var (
	ErrScopeNotFound = storage.ErrScopeNotFound
	ErrScopeExists   = storage.ErrScopeExists
)

// validateScopeForWrite is the sqlite engine's copy of the shared
// write-validation contract.  The PG engine (storage/postgres/scope.go)
// implements the identical rules; the rules are also mirrored here
// verbatim so both engines stay in lock-step by construction.
func validateScopeForWrite(sc *storage.Scope) error {
	if sc == nil {
		return fmt.Errorf("E_DB_USAGE: scope is nil")
	}
	if err := normalizeScopeValue(sc); err != nil {
		return err
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

// normalizeScopeValue canonicalizes sc.Value in place per kind (the
// domain-suffix wildcard prefix is stripped; ip/cidr go through the
// suppression engine's normalizers — the same helper the suppression
// paths use, so both scopes and suppressions accept identical forms).
func normalizeScopeValue(sc *storage.Scope) error {
	var err error
	switch sc.Kind {
	case storage.ScopeKindDomain, storage.ScopeKindDomainSuffix:
		var canonical string
		canonical, err = suppress.NormalizeDomain(sc.Value)
		if err == nil && sc.Kind == storage.ScopeKindDomainSuffix && len(canonical) > 2 && canonical[:2] == "*." {
			canonical = canonical[2:]
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
	return nil
}

const scopeColumns = `id, kind, value, mode, note, protocols, ports,
    expires_at, revoked_at, max_concurrency, max_requests, max_total_bytes, created_at`

// scanScopeRow maps one scopes row into the canonical type.
func scanScopeRow(scanner interface{ Scan(...any) error }) (storage.Scope, error) {
	var (
		sc      storage.Scope
		protos  string
		ports   string
		expires sql.NullString
		revoked sql.NullString
	)
	var created string
	if err := scanner.Scan(&sc.ID, &sc.Kind, &sc.Value, &sc.Mode, &sc.Note,
		&protos, &ports, &expires, &revoked,
		&sc.MaxConcurrency, &sc.MaxRequests, &sc.MaxTotalBytes, &created); err != nil {
		return storage.Scope{}, err
	}
	sc.Protocols = splitCSV(protos)
	var perr error
	sc.Ports, perr = storage.ParseScopePortsCSV(ports)
	if perr != nil {
		return storage.Scope{}, fmt.Errorf("sqlite: scope %d ports: %w", sc.ID, perr)
	}
	if expires.Valid && expires.String != "" {
		t, terr := ParseTS(expires.String)
		if terr != nil {
			return storage.Scope{}, fmt.Errorf("sqlite: scope %d expires_at: %w", sc.ID, terr)
		}
		sc.ExpiresAt = &t
	}
	if revoked.Valid && revoked.String != "" {
		t, terr := ParseTS(revoked.String)
		if terr != nil {
			return storage.Scope{}, fmt.Errorf("sqlite: scope %d revoked_at: %w", sc.ID, terr)
		}
		sc.RevokedAt = &t
	}
	createdTS, cerr := ParseTS(created)
	if cerr != nil {
		return storage.Scope{}, fmt.Errorf("sqlite: scope %d created_at: %w", sc.ID, cerr)
	}
	sc.CreatedAt = createdTS
	return sc, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	err := withTx(ctx, s.DB, func(tx Querier) error {
		var existing int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM scopes WHERE kind = ? AND value = ?`,
			string(sc.Kind), sc.Value).Scan(&existing)
		switch {
		case err == nil:
			return ErrScopeExists
		case isNoRows(err):
			res, ierr := tx.ExecContext(ctx, `INSERT INTO scopes
                (kind, value, mode, note, protocols, ports, expires_at, revoked_at,
                 max_concurrency, max_requests, max_total_bytes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				string(sc.Kind), sc.Value, sc.Mode, sc.Note,
				strings.Join(sc.Protocols, ","), storage.ScopePortsCSV(sc.Ports),
				tsOrNull(sc.ExpiresAt), tsOrNull(sc.RevokedAt),
				sc.MaxConcurrency, sc.MaxRequests, sc.MaxTotalBytes,
				FormatTS(sc.CreatedAt.UTC()))
			if ierr != nil {
				return ierr
			}
			id, ierr = res.LastInsertId()
			return ierr
		default:
			return err
		}
	})
	if err != nil {
		if errors.Is(err, ErrScopeExists) {
			return 0, fmt.Errorf("E_SCOPE_EXISTS: a %s scope for %q already exists (id lookup: gseer scope list) — revoke it and create a replacement, or use the existing scope: %w",
				sc.Kind, sc.Value, ErrScopeExists)
		}
		return 0, fmt.Errorf("sqlite: cannot create scope: %w", err)
	}
	sc.ID = id
	return id, nil
}

func tsOrNull(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return FormatTS(t.UTC())
}

// GetScope resolves one scope by id.
func (s *Store) GetScope(ctx context.Context, id int64) (storage.Scope, error) {
	sc, err := scanScopeRow(s.DB.QueryRowContext(ctx,
		`SELECT `+scopeColumns+` FROM scopes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return storage.Scope{}, ErrScopeNotFound
	}
	return sc, err
}

// ListScopes returns every scope (active, expired and revoked — the
// registry keeps its history; Scope.Active separates the live ones).
func (s *Store) ListScopes(ctx context.Context) ([]storage.Scope, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+scopeColumns+` FROM scopes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: cannot list scopes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storage.Scope
	for rows.Next() {
		sc, serr := scanScopeRow(rows)
		if serr != nil {
			return nil, fmt.Errorf("sqlite: cannot list scopes: %w", serr)
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: cannot list scopes: %w", err)
	}
	return out, nil
}

// RevokeScope marks one scope revoked (UPDATE revoked_at; the row stays
// as history).  Returns whether a live row was revoked.
func (s *Store) RevokeScope(ctx context.Context, id int64, when time.Time) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE scopes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		FormatTS(when.UTC()), id)
	if err != nil {
		return false, fmt.Errorf("sqlite: cannot revoke scope %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("sqlite: cannot revoke scope %d: %w", id, err)
	}
	return n > 0, nil
}

// InsertScanAudit appends one gateway decision to scan_audits.
func (s *Store) InsertScanAudit(ctx context.Context, rec *storage.ScanAudit) error {
	if rec.TS.IsZero() {
		rec.TS = time.Now().UTC()
	}
	detail := "{}"
	if rec.Detail != nil {
		b, err := json.Marshal(rec.Detail)
		if err != nil {
			return fmt.Errorf("E_DB_USAGE: scan audit detail not JSON-serializable: %w", err)
		}
		detail = string(b)
	}
	var id int64
	err := withTx(ctx, s.DB, func(tx Querier) error {
		res, ierr := tx.ExecContext(ctx, `INSERT INTO scan_audits
            (ts, target_host, target_ip, port, protocol, decision, reason, scope_id, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			FormatTS(rec.TS.UTC()), rec.TargetHost, rec.TargetIP, rec.Port, rec.Protocol,
			rec.Decision, rec.Reason, rec.ScopeID, detail)
		if ierr != nil {
			return ierr
		}
		id, ierr = res.LastInsertId()
		return ierr
	})
	if err != nil {
		return fmt.Errorf("sqlite: cannot record scan audit: %w", err)
	}
	rec.ID = id
	return nil
}

// ListScanAudits returns the most recent audit rows (limit 0 = 100).
func (s *Store) ListScanAudits(ctx context.Context, limit int) ([]storage.ScanAudit, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, ts, target_host, target_ip, port,
        protocol, decision, reason, scope_id, detail
        FROM scan_audits ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("sqlite: cannot list scan audits: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storage.ScanAudit
	for rows.Next() {
		var (
			rec    storage.ScanAudit
			tsRaw  string
			detail string
		)
		if err := rows.Scan(&rec.ID, &tsRaw, &rec.TargetHost, &rec.TargetIP,
			&rec.Port, &rec.Protocol, &rec.Decision, &rec.Reason, &rec.ScopeID, &detail); err != nil {
			return nil, fmt.Errorf("sqlite: cannot list scan audits: %w", err)
		}
		if t, terr := ParseTS(tsRaw); terr == nil {
			rec.TS = t
		}
		if detail != "" && detail != "{}" {
			_ = json.Unmarshal([]byte(detail), &rec.Detail)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: cannot list scan audits: %w", err)
	}
	return out, nil
}
