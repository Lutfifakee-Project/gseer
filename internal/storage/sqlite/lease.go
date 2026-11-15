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
	"fmt"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// lease.go — the personal engine's cross-process max_concurrency
// enforcement (v0.3.2 microfix 0003 + final-security-microfix 0004):
// the exact PostgreSQL contract (storage/postgres/lease.go) lowered to
// database/sql + the personal dialect (fixed-width UTC TEXT
// timestamps, whose lexicographic order IS chronological order — the
// same SQ-02 property the scopes/audits columns rely on).
//
// Ownership identity is the per-acquisition TOKEN
// (storage.NewLeaseToken, 128-bit crypto/rand hex) — never the PID,
// hostname or timestamp:
//
//	acquire  one withTx per slot (the DSN takes the write lock at
//	         BEGIN, so the read-then-write is serialized across
//	         processes sharing the file): SELECT the slot, INSERT when
//	         free, UPDATE-steal only when the held row's expires_at has
//	         passed.
//	renew    UPDATE expires_at WHERE (scope_id, slot, token) AND
//	         expires_at > now — extends ONLY the caller's own LIVE row;
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
// expired rows.  maxConcurrency < 1 is treated as 1; ttl <= 0 uses
// storage.DefaultScanLeaseTTL.
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

	for slot := 1; slot <= maxConcurrency; slot++ {
		var (
			lease     *storage.ScanLease
			heldUntil string
		)
		err := withTx(ctx, s.DB, func(tx Querier) error {
			row := tx.QueryRowContext(ctx,
				`SELECT expires_at FROM scan_leases WHERE scope_id = ? AND slot = ?`,
				scopeID, slot)
			serr := row.Scan(&heldUntil)
			switch {
			case isNoRows(serr):
				// Slot free — claim it inside the same write transaction.
				_, ierr := tx.ExecContext(ctx, `INSERT INTO scan_leases
                    (scope_id, slot, holder, token, acquired_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)`,
					scopeID, slot, holder, token, FormatTS(now), FormatTS(expires))
				if ierr != nil {
					return ierr
				}
				lease = &storage.ScanLease{
					ScopeID:    scopeID,
					Slot:       slot,
					Holder:     holder,
					Token:      token,
					AcquiredAt: now,
					ExpiresAt:  expires,
				}
				return nil
			case serr != nil:
				return serr
			default:
				return nil // slot held; heldUntil carries the expiry
			}
		})
		if err != nil {
			return nil, fmt.Errorf("cannot acquire the scope concurrency lease: %w", err)
		}
		if lease != nil {
			return lease, nil
		}

		// Slot held — stealable only when the held lease has expired.
		heldExpiry, perr := ParseTS(heldUntil)
		if perr == nil && !heldExpiry.After(now) {
			var stolen *storage.ScanLease
			serr := withTx(ctx, s.DB, func(tx Querier) error {
				res, uerr := tx.ExecContext(ctx, `UPDATE scan_leases
                    SET holder = ?, token = ?, acquired_at = ?, expires_at = ?
                    WHERE scope_id = ? AND slot = ? AND expires_at <= ?`,
					holder, token, FormatTS(now), FormatTS(expires), scopeID, slot, FormatTS(now))
				if uerr != nil {
					return uerr
				}
				n, aerr := res.RowsAffected()
				if aerr != nil {
					return aerr
				}
				if n > 0 {
					stolen = &storage.ScanLease{
						ScopeID:    scopeID,
						Slot:       slot,
						Holder:     holder,
						Token:      token,
						AcquiredAt: now,
						ExpiresAt:  expires,
					}
				}
				return nil
			})
			if serr != nil {
				return nil, fmt.Errorf("cannot acquire the scope concurrency lease: %w", serr)
			}
			if stolen != nil {
				return stolen, nil
			}
		}
		// Live lease on this slot — try the next one.
	}
	return nil, fmt.Errorf("E_SCOPE_BUSY: scope %d is already at its max_concurrency=%d limit of simultaneous observations: %w",
		scopeID, maxConcurrency, storage.ErrScopeBusy)
}

// RenewScanLease extends the caller's OWN live lease by ttl.  The
// update matches (scope_id, slot, token) AND expires_at > now, so it
// can never resurrect a lease that lapsed or was stolen by another
// holder.  Zero rows updated ⇒ storage.ErrLeaseLost; any other error
// is a storage failure — callers fail closed either way.
func (s *Store) RenewScanLease(ctx context.Context, lease *storage.ScanLease, ttl time.Duration) error {
	if lease == nil || lease.Token == "" {
		return fmt.Errorf("E_SCOPE_BUSY: cannot renew a lease without a token: %w", storage.ErrLeaseLost)
	}
	if ttl <= 0 {
		ttl = storage.DefaultScanLeaseTTL
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	res, err := s.DB.ExecContext(ctx, `UPDATE scan_leases
        SET expires_at = ?
        WHERE scope_id = ? AND slot = ? AND token = ? AND expires_at > ?`,
		FormatTS(expires), lease.ScopeID, lease.Slot, lease.Token, FormatTS(now))
	if err != nil {
		return fmt.Errorf("sqlite: cannot renew the scope concurrency lease: %w", err)
	}
	n, aerr := res.RowsAffected()
	if aerr != nil {
		return fmt.Errorf("sqlite: cannot renew the scope concurrency lease: %w", aerr)
	}
	if n == 0 {
		return fmt.Errorf("E_SCOPE_BUSY: lease for scope %d slot %d is gone (expired or stolen): %w",
			lease.ScopeID, lease.Slot, storage.ErrLeaseLost)
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
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM scan_leases WHERE scope_id = ? AND slot = ? AND token = ?`,
		lease.ScopeID, lease.Slot, lease.Token)
	if err != nil {
		return fmt.Errorf("sqlite: cannot release the scope concurrency lease: %w", err)
	}
	_, _ = res.RowsAffected() // 0 = already expired/stolen/released — fine
	return nil
}
