// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

// lease_test.go — FIX D (v0.3.2 security microfix): the cross-process
// max_concurrency enforcement over the REAL personal engine
// (migration 0003's scan_leases).  The coordination state lives in the
// database file, so "cross-process" is proven with INDEPENDENT store
// handles (separate connection pools on the same file — exactly what
// two CLI processes see); the row-level protocol is identical from
// either process.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// newLeaseFixture opens a fresh personal database with one scope of
// the given max_concurrency.
func newLeaseFixture(t *testing.T, maxConcurrency int) (*Store, int64) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "lease-e2e.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := Migrate(context.Background(), db.DB); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	store := NewStore(db.DB)
	t.Cleanup(func() { _ = store.Close() })

	sc := &storage.Scope{
		Kind:           storage.ScopeKindIP,
		Value:          "127.0.0.1",
		Mode:           "allow",
		Protocols:      []string{"http"},
		Ports:          []int{8080},
		MaxConcurrency: maxConcurrency,
		MaxRequests:    1,
	}
	id, err := store.CreateScope(context.Background(), sc)
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	return store, id
}

func TestScanLeaseUnderLimitSucceeds(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 2)
	ctx := context.Background()

	l1, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-a")
	if err != nil {
		t.Fatalf("first acquire must succeed: %v", err)
	}
	l2, err := store.AcquireScanLease(ctx, scopeID, 2, 0, "proc-a")
	if err != nil {
		t.Fatalf("second acquire must succeed (limit 2): %v", err)
	}
	if l1.Slot == l2.Slot || l2.Slot < 1 || l2.Slot > 2 {
		t.Fatalf("distinct slots expected: %+v %+v", l1, l2)
	}
	if err := store.ReleaseScanLease(ctx, l1); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, l2); err != nil {
		t.Fatalf("release: %v", err)
	}
}

func TestScanLeaseExceedingLimitRejected(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-a"); err != nil {
		t.Fatalf("first acquire must succeed: %v", err)
	}
	_, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "proc-b")
	if !errors.Is(err, storage.ErrScopeBusy) || !containsStr(err.Error(), "E_SCOPE_BUSY") {
		t.Fatalf("exceeding max_concurrency=1 must return E_SCOPE_BUSY/ErrScopeBusy: %v", err)
	}
}

func TestScanLeaseSeparateHandlesCannotExceedLimit(t *testing.T) {
	// Two INDEPENDENT stores on the same database file — the exact
	// state two separate CLI processes share.  The limit holds across
	// handles because it is a DB-row protocol, not process memory.
	dbPath := filepath.Join(t.TempDir(), "lease-shared.db")
	openAt := func() *Store {
		t.Helper()
		db, err := Open(dbPath)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if _, err := Migrate(context.Background(), db.DB); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return NewStore(db.DB)
	}
	storeA := openAt()
	defer func() { _ = storeA.Close() }()
	sc := &storage.Scope{
		Kind: storage.ScopeKindIP, Value: "127.0.0.1", Mode: "allow",
		Protocols: []string{"http"}, Ports: []int{8080}, MaxConcurrency: 1, MaxRequests: 1,
	}
	scopeID, err := storeA.CreateScope(context.Background(), sc)
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	storeB := openAt()
	defer func() { _ = storeB.Close() }()

	ctx := context.Background()
	lA, err := storeA.AcquireScanLease(ctx, scopeID, 1, 0, "process-a")
	if err != nil {
		t.Fatalf("process A must take the only slot: %v", err)
	}
	_, err = storeB.AcquireScanLease(ctx, scopeID, 1, 0, "process-b")
	if !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("process B must be refused while A holds the slot: %v", err)
	}
	// A hand-built lease WITHOUT the token must NOT free A's slot (the
	// token is the ownership identity — final-security-microfix FIX B).
	if err := storeA.ReleaseScanLease(ctx, &storage.ScanLease{ScopeID: scopeID, Slot: lA.Slot, Holder: "process-a"}); err != nil {
		t.Fatalf("token-less release must be a safe no-op: %v", err)
	}
	if _, err := storeB.AcquireScanLease(ctx, scopeID, 1, 0, "process-b"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the token-less release must NOT free the held slot: %v", err)
	}
	if err := storeA.ReleaseScanLease(ctx, lA); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := storeB.AcquireScanLease(ctx, scopeID, 1, 0, "process-b"); err != nil {
		t.Fatalf("after A releases (token-scoped), B must acquire: %v", err)
	}
}

func TestScanLeaseExpiredLeaseRecovery(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	// A crashed holder: acquire a live lease, then simulate the crash
	// + TTL passing by pushing the row's expiry into the past (the
	// acquire path deliberately clamps a negative TTL to the default).
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "crashed-proc"); err != nil {
		t.Fatalf("seed the lease: %v", err)
	}
	past := time.Now().UTC().Add(-time.Hour).Format(tsLayout)
	if _, err := store.DB.ExecContext(ctx, `UPDATE scan_leases SET expires_at = ?`, past); err != nil {
		t.Fatalf("expire the crashed holder's lease: %v", err)
	}
	l, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "recovery-proc")
	if err != nil {
		t.Fatalf("the expired lease must be STEALABLE (crash recovery): %v", err)
	}
	if l.Holder != "recovery-proc" {
		t.Fatalf("the stealer owns the slot: %+v", l)
	}
	// Stealing must never delete another live lease: a fresh live lease
	// blocks the next acquirer again.
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "blocked-proc"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the stolen (live) lease must block: %v", err)
	}
}

func TestScanLeaseReleaseIsTokenScoped(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()

	owner, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "owner")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// A foreign lease (wrong token) cannot release the owner's row —
	// neither hand-built nor stolen: the token is the ownership key.
	if err := store.ReleaseScanLease(ctx, &storage.ScanLease{ScopeID: scopeID, Slot: owner.Slot, Holder: "attacker"}); err != nil {
		t.Fatalf("release of a foreign row is a no-op success: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, &storage.ScanLease{ScopeID: scopeID, Slot: owner.Slot, Holder: owner.Holder, Token: "forged-token"}); err != nil {
		t.Fatalf("a forged token must not free the slot (no-op success): %v", err)
	}
	if _, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "next"); !errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("the owner's lease must survive foreign/forged release attempts: %v", err)
	}
	// Double release is safe: the second is a token-scoped no-op.
	if err := store.ReleaseScanLease(ctx, owner); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := store.ReleaseScanLease(ctx, owner); err != nil {
		t.Fatalf("double release must be a no-op success: %v", err)
	}
}

func TestScanLeaseDatabaseErrorFailsClosed(t *testing.T) {
	store, scopeID := newLeaseFixture(t, 1)
	ctx := context.Background()
	// Kill the engine underneath: every subsequent acquire must return
	// a REAL error (fail closed) — never a silent success, never busy.
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err := store.AcquireScanLease(ctx, scopeID, 1, 0, "post-close")
	if err == nil {
		t.Fatalf("a storage failure must FAIL CLOSED with an error")
	}
	if errors.Is(err, storage.ErrScopeBusy) {
		t.Fatalf("a storage failure is not a busy answer: %v", err)
	}
}
