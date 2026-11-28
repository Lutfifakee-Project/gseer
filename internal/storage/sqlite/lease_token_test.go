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

// lease_token_test.go — FINAL-security-microfix FIX B: lease ownership
// tokens and renewal over the REAL personal engine (migration 0004).
// Deterministic: expiry is simulated by pushing expires_at into the
// past with direct SQL (no sleeps); renewal cadence is injected at the
// observe layer.  The PostgreSQL twin lives in
// internal/storage/postgres/lease_token_integration_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// expireAll pushes every lease row's expiry into the past (deterministic
// "time has passed" without sleeping).
func expireAll(t *testing.T, store *Store) {
	t.Helper()
	past := time.Now().UTC().Add(-time.Hour).Format(tsLayout)
	if _, err := store.DB.ExecContext(context.Background(),
		`UPDATE scan_leases SET expires_at = ?`, past); err != nil {
		t.Fatalf("expire rows: %v", err)
	}
}

func TestScanLeaseTokensUniquePerAcquisition(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 2)
	ctx := context.Background()

	l1, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "same-process")
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	l2, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "same-process")
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if l1.Token == "" || l2.Token == "" {
		t.Fatalf("tokens must be non-empty: %q %q", l1.Token, l2.Token)
	}
	if l1.Token == l2.Token {
		t.Fatalf("two acquisitions in the SAME process must have different tokens: %q", l1.Token)
	}
	if len(l1.Token) < 32 {
		t.Fatalf("token must carry real entropy (128-bit hex): %q", l1.Token)
	}
}

func TestScanLeaseLateReleaseCannotDeleteNewerLease(t *testing.T) {
	// THE defect regression (FIX B): with the old holder#pid identity,
	// a late-finishing observation's release deleted the newer
	// observation's lease on the same slot.  With tokens, it cannot.
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	old, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "same-process")
	if err != nil {
		t.Fatalf("old acquire: %v", err)
	}
	expireAll(t, store)
	// The newer observation STEALS the slot — in this simulation the
	// same process (identical holder string); only tokens differ.
	fresh, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "same-process")
	if err != nil {
		t.Fatalf("steal: %v", err)
	}
	if fresh.Token == old.Token {
		t.Fatalf("the stealer must own a DIFFERENT token")
	}
	// The OLD observation finishes late and releases ITS lease.
	if err := store.ReleaseScanLease(ctx, old); err != nil {
		t.Fatalf("old release: %v", err)
	}
	// The NEW lease must survive untouched.
	l3, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "next-proc")
	if !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the newer holder's lease must survive the old release (got %v)", err)
	}
	_ = l3
	// And the new holder releases fine afterwards.
	if err := store.ReleaseScanLease(ctx, fresh); err != nil {
		t.Fatalf("fresh release: %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "next-proc"); err != nil {
		t.Fatalf("slot free after the REAL holder releases: %v", err)
	}
}

func TestScanLeaseRenewalExtendsOwnLease(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	l, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	before := l.ExpiresAt
	if err := store.RenewScanLease(ctx, l, 5*time.Minute); err != nil {
		t.Fatalf("renewal of the owner's own live lease must succeed: %v", err)
	}
	if !l.ExpiresAt.After(before) {
		t.Fatalf("renewal must extend the expiry: %v -> %v", before, l.ExpiresAt)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-b"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the renewed lease must still block: %v", err)
	}
}

func TestScanLeaseRenewalRefusesStolenLease(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	old, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	expireAll(t, store)
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "stealer"); err != nil {
		t.Fatalf("steal: %v", err)
	}
	if err := store.RenewScanLease(ctx, old, time.Minute); !errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("renewing a STOLEN lease must return ErrLeaseLost, got %v", err)
	}
}

func TestScanLeaseRenewalRefusesLapsedLease(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	l, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	expireAll(t, store)
	// Not yet stolen — but lapsed: renewal must refuse (conservative:
	// the slot may be stolen the instant after; a resurrected lease
	// would break the limit).
	if err := store.RenewScanLease(ctx, l, time.Minute); !errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("renewing a LAPSED lease must return ErrLeaseLost, got %v", err)
	}
}

func TestScanLeaseRenewalWithoutTokenFails(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()
	fake := &storage.ScanLease{ScopeID: scopeID, Slot: 1}
	if err := store.RenewScanLease(ctx, fake, time.Minute); !errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("renewal without a token must fail with ErrLeaseLost, got %v", err)
	}
}

func TestScanLeaseRenewalDatabaseErrorFailsClosed(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()
	l, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-a")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	err = store.RenewScanLease(ctx, l, time.Minute)
	if err == nil {
		t.Fatalf("a renewal storage failure must FAIL CLOSED with an error")
	}
	if errors.Is(err, storage.ErrLeaseLost) {
		t.Fatalf("a storage failure is a DIFFERENT failure class than a lost lease: %v", err)
	}
}

func TestScanLeasePerScopeLimitsAreIndependent(t *testing.T) {
	store, scopeA := newLeaseFixture(t, 1)
	ctx := context.Background()
	// A second scope on the same engine has its OWN budget.
	sc := &storage.Scope{
		Kind: storage.ScopeKindIP, Value: "127.0.0.2", Mode: "allow",
		Protocols: []string{"http"}, Ports: []int{8080}, MaxConcurrency: 1, MaxRequests: 1,
	}
	scopeB, err := store.CreateScope(ctx, sc)
	if err != nil {
		t.Fatalf("create scope B: %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeA, 1, 0, "proc-a"); err != nil {
		t.Fatalf("A: %v", err)
	}
	lb, err := store.AcquireScanLease(ctx, scopeB, 1, 0, "proc-b")
	if err != nil {
		t.Fatalf("scope B must follow ITS OWN limit (A's lease is irrelevant): %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeB, 1, 0, "proc-c"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("B at its own limit: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, lb); err != nil {
		t.Fatalf("release B: %v", err)
	}
}
