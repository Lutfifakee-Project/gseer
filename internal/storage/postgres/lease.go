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

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// lease.go — the cross-process max_concurrency enforcement (v0.3.2
// microfix 0019 + final-security-microfix 0020).  One observation run
// holds one scan_leases slot (1..max_concurrency) of its acting scope
// for the run's duration; every process coordinates through these rows.
//
// Ownership identity is the per-acquisition TOKEN (storage.NewLeaseToken,
// 128-bit crypto/rand hex) — never the PID, hostname or timestamp:
//
//	acquire  INSERT (scope_id, slot, token) with expires_at = now + TTL,
//	         or — on a (scope_id, slot) conflict — an atomic steal of the
//	         row only when its expires_at has passed.
//	renew    UPDATE expires_at WHERE (scope_id, slot, token) AND
//	         expires_at > now: extends ONLY the caller's own LIVE row —
//	         a stolen or lapsed lease can never be resurrected
//	         (storage.ErrLeaseLost).
//	release  DELETE WHERE (scope_id, slot, token): an old holder's late
//	         release can never remove a newer holder's lease; double
//	         release is a no-op success.
//	crash    the TTL (storage.DefaultScanLeaseTTL) bounds an abandoned
//	         row; stale locks never accumulate without limit.
//
// holder stays diagnostic provenance (host#pid); it is NOT the key.

// AcquireScanLease takes one of the scope's lease slots, stealing only
// expired rows.  maxConcurrency < 1 is treated as 1 (the storage
// validator's floor); ttl <= 0 uses storage.DefaultScanLeaseTTL.
func (s *Store) AcquireScanLease(ctx context.Context, scopeID int64, maxConcurrency int, ttl time.Duration, holder string) (*storage.ScanLease, error) {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	if ttl <= 0 {
		ttl = storage.DefaultScanLeaseTTL
	}
	token, terr := storage.NewLeaseToken()
	if terr != nil {
		return nil, fmt.Errorf("cannot acquire the scope concurrency lease: %w", terr)
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)

	const leaseSQL = `INSERT INTO scan_leases (scope_id, slot, holder, token, acquired_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (scope_id, slot) DO UPDATE
            SET holder = $3, token = $4, acquired_at = $5, expires_at = $6
            WHERE scan_leases.expires_at <= $5
        RETURNING slot`

	for slot := 1; slot <= maxConcurrency; slot++ {
		err := s.pool.QueryRow(ctx, leaseSQL,
			scopeID, slot, holder, token, now, expires).Scan(&slot)
		if err == nil {
			return &storage.ScanLease{
				ScopeID:    scopeID,
				Slot:       slot,
				Holder:     holder,
				Token:      token,
				AcquiredAt: now,
				ExpiresAt:  expires,
			}, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("cannot acquire the scope concurrency lease: %w", err)
		}
		// Slot held by a live lease — try the next slot.
	}
	return nil, fmt.Errorf("E_SCOPE_BUSY: scope %d is already at its max_concurrency=%d limit of simultaneous observations: %w",
		scopeID, maxConcurrency, storage.ErrScopeBusy)
}

// RenewScanLease extends the caller's OWN live lease by ttl.  The
// update matches (scope_id, slot, token) AND expires_at > now, so it
// can never resurrect a lease that lapsed or was stolen by another
// holder.  Zero rows updated ⇒ storage.ErrLeaseLost (the observation
// must not open any new connection); any other error is a storage
// failure — callers fail closed either way.
func (s *Store) RenewScanLease(ctx context.Context, lease *storage.ScanLease, ttl time.Duration) error {
	if lease == nil || lease.Token == "" {
		return fmt.Errorf("E_SCOPE_BUSY: cannot renew a lease without a token: %w", storage.ErrLeaseLost)
	}
	if ttl <= 0 {
		ttl = storage.DefaultScanLeaseTTL
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	var slot int
	err := s.pool.QueryRow(ctx,
		`UPDATE scan_leases SET expires_at = $5
         WHERE scope_id = $1 AND slot = $2 AND token = $3 AND expires_at > $4
         RETURNING slot`,
		lease.ScopeID, lease.Slot, lease.Token, now, expires).Scan(&slot)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("E_SCOPE_BUSY: lease for scope %d slot %d is gone (expired or stolen): %w",
			lease.ScopeID, lease.Slot, storage.ErrLeaseLost)
	}
	if err != nil {
		return fmt.Errorf("cannot renew the scope concurrency lease: %w", err)
	}
	lease.ExpiresAt = expires
	return nil
}

// ReleaseScanLease deletes the caller's own lease row — matched by
// (scope_id, slot, TOKEN), so a stale late release from the same
// process can never delete a newer holder's lease.  Releasing an
// expired/stolen/absent row is a no-op success — release is best-effort
// by contract; the TTL bounds any leak.
func (s *Store) ReleaseScanLease(ctx context.Context, lease *storage.ScanLease) error {
	if lease == nil {
		return nil
	}
	if lease.Token == "" {
		return nil // nothing token-ownable to release (legacy row) — TTL bounds it
	}
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM scan_leases WHERE scope_id = $1 AND slot = $2 AND token = $3`,
		lease.ScopeID, lease.Slot, lease.Token)
	if err != nil {
		return fmt.Errorf("cannot release the scope concurrency lease: %w", err)
	}
	_ = tag.RowsAffected() // 0 = already expired/stolen/released — fine
	return nil
}
