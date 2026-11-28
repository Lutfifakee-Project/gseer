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

//go:build integration

package postgres

// lease_token_integration_test.go — FINAL-security-microfix FIX B over
// the REAL PostgreSQL engine, through the REAL migration chain to the
// new head (0020), under the pinned deployment order.  The exact twin
// of the personal engine's matrix (lease_token_test.go) plus the
// two-independent-pools cross-process proof.  Deterministic: expiry is
// simulated with UPDATE expires_at (no sleeps).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func TestScanLeaseTokensOnPostgres(t *testing.T) {
	ctx := context.Background()
	dsn, cleanup := testDB(t)
	defer cleanup()

	if _, err := BootstrapRoles(ctx, dsn); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, head, err := RunMigrations(dsn, lockTimeoutForTest()); err != nil {
		t.Fatalf("migrations: %v", err)
	} else if head != 21 {
		t.Fatalf("migration head = %d, want 21 (…0019 + 0020 + 0021_cert_projection)", head)
	}
	if _, err := ApplyRuntimeGrants(ctx, dsn); err != nil {
		t.Fatalf("runtime grants: %v", err)
	}
	if report, err := RunPrivilegeAudit(ctx, dsn); err != nil {
		t.Fatalf("privilege audit could not run: %v", err)
	} else if !report.Passed {
		t.Fatalf("fail-closed privilege audit FAILED after 0020: %v", report.Failures)
	}

	pool, err := NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	store := NewStore(pool)
	pool2, err := NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("pool 2: %v", err)
	}
	defer pool2.Close()
	storeB := NewStore(pool2)

	sc := &storage.Scope{
		Kind:           storage.ScopeKindIP,
		Value:          "127.0.0.1",
		Mode:           "allow",
		Protocols:      []string{"http"},
		Ports:          []int{8080},
		MaxConcurrency: 1,
		MaxRequests:    1,
	}
	scopeID, err := store.CreateScope(ctx, sc)
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}

	// 1. Tokens: unique, non-empty, per acquisition — even within one
	// process.
	l1, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "same-proc")
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if l1.Token == "" || len(l1.Token) < 32 {
		t.Fatalf("token must carry 128-bit hex entropy: %q", l1.Token)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "same-proc"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("limit 1 must hold: %v", err)
	}

	// 2. THE defect regression: expire the old lease, let another pool
	// (another process) steal the slot, then the OLD holder releases —
	// the stealer's lease must survive untouched.
	if _, err := pool.Exec(ctx,
		`UPDATE scan_leases SET expires_at = now() - interval '1 hour' WHERE scope_id = $1`,
		scopeID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	fresh, err := storeB.AcquireScanLease(ctx, scopeID, 1, 0, "process-b")
	if err != nil {
		t.Fatalf("steal from the other pool: %v", err)
	}
	if fresh.Token == l1.Token {
		t.Fatalf("the stealer must own a DIFFERENT token")
	}
	if err := store.ReleaseScanLease(ctx, l1); err != nil {
		t.Fatalf("old release: %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "late-comer"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the newer holder's lease must survive the old release: %v", err)
	}

	// 3. Renewal: token-scoped — the stealer extends its own lease; the
	// OLD token's renewal is refused (ErrLeaseLost).
	if err := storeB.RenewScanLease(ctx, fresh, time.Minute); err != nil {
		t.Fatalf("the live holder's renewal must succeed: %v", err)
	}
	if err := store.RenewScanLease(ctx, l1, time.Minute); !errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("renewing the STOLEN lease must return ErrLeaseLost, got %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "next"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the renewed lease must still block: %v", err)
	}

	// 4. A LAPSED lease refuses renewal even before anyone steals it.
	l2, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-c")
	if err != nil {
		t.Fatalf("acquire on slot 2: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE scan_leases SET expires_at = now() - interval '1 hour' WHERE scope_id = $1 AND token = $2`,
		scopeID, l2.Token); err != nil {
		t.Fatalf("expire l2: %v", err)
	}
	if err := store.RenewScanLease(ctx, l2, time.Minute); !errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("renewing a LAPSED lease must return ErrLeaseLost, got %v", err)
	}

	// 5. Release frees exactly the owner's slot; double release is safe.
	if err := store.ReleaseScanLease(ctx, fresh); err != nil {
		t.Fatalf("fresh release: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, fresh); err != nil {
		t.Fatalf("double release must be a no-op success: %v", err)
	}
	l3, err := storeB.AcquireScanLease(ctx, scopeID, 1, 0, "final-proc")
	if err != nil {
		t.Fatalf("slot free after release: %v", err)
	}
	if l3.Slot != fresh.Slot {
		t.Fatalf("the released slot must be reusable: %+v", l3)
	}

	// 6. The token column carries its corrected-semantics comment (0020).
	var cm int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_description d
        JOIN pg_class c ON c.oid = d.objoid AND c.relname = 'scan_leases'
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        WHERE d.objsubid = (SELECT attnum FROM pg_attribute WHERE attrelid = c.oid AND attname = 'token')`).Scan(&cm); err != nil {
		t.Fatalf("comment probe: %v", err)
	}
	if cm != 1 {
		t.Fatalf("scan_leases.token carries %d comments, want 1 (0020 contract)", cm)
	}
}
