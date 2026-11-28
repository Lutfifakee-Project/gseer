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

// lease_integration_test.go — FIX D (v0.3.2 security microfix): the
// cross-process max_concurrency enforcement over the REAL PostgreSQL
// engine, through the REAL migration chain to the new head (0019), under
// the pinned deployment order (bootstrap → migrate → grants → audit).
// Proven here:
//
//   1. migration 0019 applies (scan_leases + corrected-semantics column
//      comments) and the fail-closed effective-privilege audit still
//      passes with the additive lease grants;
//   2. the lease protocol behaves EXACTLY like the personal engine
//      (parity): under-limit acquire, limit rejection, two independent
//      pools (= two processes) cannot exceed the limit, expired-lease
//      recovery, holder-scoped release.

import (
	"context"
	"errors"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func TestScanLeasesOnPostgres(t *testing.T) {
	ctx := context.Background()
	dsn, cleanup := testDB(t)
	defer cleanup()

	if _, err := BootstrapRoles(ctx, dsn); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	applied, head, err := RunMigrations(dsn, lockTimeoutForTest())
	if err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if head != 21 {
		t.Fatalf("migration head = %d, want 21 (0019 + 0020 + 0021_cert_projection)", head)
	}
	if applied < 1 {
		t.Fatalf("fresh database applied %d migrations, want the full set", applied)
	}
	if _, err := ApplyRuntimeGrants(ctx, dsn); err != nil {
		t.Fatalf("runtime grants: %v", err)
	}
	report, err := RunPrivilegeAudit(ctx, dsn)
	if err != nil {
		t.Fatalf("privilege audit could not run: %v", err)
	}
	if !report.Passed {
		t.Fatalf("fail-closed privilege audit FAILED after 0019: %v", report.Failures)
	}

	pool, err := NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("app pool: %v", err)
	}
	defer pool.Close()
	store := NewStore(pool)

	sc := &storage.Scope{
		Kind:           storage.ScopeKindIP,
		Value:          "127.0.0.1",
		Mode:           "allow",
		Protocols:      []string{"http"},
		Ports:          []int{8080},
		MaxConcurrency: 2,
		MaxRequests:    1,
	}
	scopeID, err := store.CreateScope(ctx, sc)
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}

	// 1. Under-limit: two slots acquire, each on its own slot.
	l1, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-a")
	if err != nil {
		t.Fatalf("first acquire must succeed: %v", err)
	}
	l2, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-a")
	if err != nil {
		t.Fatalf("second acquire must succeed (limit 2): %v", err)
	}
	if l1.Slot == l2.Slot {
		t.Fatalf("distinct slots expected: %+v %+v", l1, l2)
	}

	// 2. Exceeding the limit is rejected with the shared sentinel.
	if _, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-c"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("third concurrent acquire must be E_SCOPE_BUSY: %v", err)
	}

	// 3. The limit binds across INDEPENDENT connection pools — the exact
	// state two separate CLI processes share (the protocol is DB rows).
	pool2, err := NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("second app pool: %v", err)
	}
	defer pool2.Close()
	storeB := NewStore(pool2)
	if _, err := storeB.AcquireScanLease(ctx, scopeID, 2, 0, "proc-d"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("a second process must be refused while both slots are held: %v", err)
	}

	// 4. Release is holder-scoped and frees exactly one slot.
	if err := store.ReleaseScanLease(ctx, l1); err != nil {
		t.Fatalf("release: %v", err)
	}
	lB, err := storeB.AcquireScanLease(ctx, scopeID, 2, 0, "proc-d")
	if err != nil {
		t.Fatalf("freed slot must be acquirable from the other pool: %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-e"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the still-held second slot must block: %v", err)
	}

	// 5. Expired-lease recovery: a crashed holder's expired slot is
	// stealable.  Free both slots, seed two live leases, then simulate
	// one holder's crash + TTL passing by pushing ONLY its row's expiry
	// into the past (the acquire path deliberately clamps a non-positive
	// TTL to the default).
	if err := store.ReleaseScanLease(ctx, l2); err != nil {
		t.Fatalf("release l2: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, lB); err != nil {
		t.Fatalf("release proc-d: %v", err)
	}
	l3, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "crashed-proc")
	if err != nil {
		t.Fatalf("seed the crashed holder's lease: %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "live-owner"); err != nil {
		t.Fatalf("seed the live owner: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE scan_leases SET expires_at = now() - interval '1 hour' WHERE scope_id = $1 AND holder = 'crashed-proc'`,
		scopeID); err != nil {
		t.Fatalf("expire the crashed holder's lease: %v", err)
	}
	l4, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "recovery-proc")
	if err != nil {
		t.Fatalf("the expired lease must be STEALABLE (crash recovery): %v", err)
	}
	if l4.Slot != l3.Slot || l4.Holder != "recovery-proc" {
		t.Fatalf("the stealer owns the stolen slot: %+v vs %+v", l4, l3)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "blocked-proc"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the live owner's slot must still block: %v", err)
	}

	// 6. The corrected-semantics comments (FIX E) are in place.
	var cm int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_description d
        JOIN pg_class c ON c.oid = d.objoid AND c.relname = 'scopes'
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        WHERE d.objsubid IN (
            (SELECT attnum FROM pg_attribute WHERE attrelid = c.oid AND attname = 'max_total_bytes'),
            (SELECT attnum FROM pg_attribute WHERE attrelid = c.oid AND attname = 'max_concurrency'))`).Scan(&cm); err != nil {
		t.Fatalf("comment probe: %v", err)
	}
	if cm != 2 {
		t.Fatalf("max_total_bytes/max_concurrency carry %d corrected-semantics comments, want 2", cm)
	}
}
