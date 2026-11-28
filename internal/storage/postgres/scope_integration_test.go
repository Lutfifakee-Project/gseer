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

// scope_integration_test.go — v0.3.2: the active-observation surface on
// the REAL PostgreSQL engine, over the REAL migration chain through the
// new head (0018).  Proven here:
//
//   1. the full migration set (…→ 0016 + 0017 + 0018) applies under the
//      pinned deployment order (bootstrap → migrate → grants → audit);
//   2. the scope registry CRUD works (create/list/get/revoke, uniqueness);
//   3. the append-only scan audit works;
//   4. the additive gseer_app grants from 0018 are in effect;
//   5. THE FAIL-CLOSED EFFECTIVE-PRIVILEGE AUDIT STILL PASSES — the
//      active-observation surface did not weaken the hardened contract.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func TestScopeRegistryOnPostgres(t *testing.T) {
	ctx := context.Background()
	dsn, cleanup := testDB(t)
	defer cleanup()

	// The pinned deployment order (the same one upgrade_test rehearses).
	if _, err := BootstrapRoles(ctx, dsn); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	applied, head, err := RunMigrations(dsn, lockTimeoutForTest())
	if err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if head != 21 {
		t.Fatalf("migration head = %d, want 21 (…0019_scan_concurrency_leases + 0020_scan_lease_tokens + 0021_cert_projection)", head)
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
		t.Fatalf("fail-closed privilege audit FAILED after 0018: %v", report.Failures)
	}

	pool, err := NewPool(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	store := NewStore(pool)

	// ---- scope CRUD. ----
	expires := time.Now().UTC().Add(24 * time.Hour)
	sc := &storage.Scope{
		Kind:           storage.ScopeKindCIDR,
		Value:          "127.0.0.1/32",
		Mode:           "allow",
		Note:           "integration loopback scope",
		Protocols:      []string{"http", "tls"},
		Ports:          []int{8080, 8443},
		ExpiresAt:      &expires,
		MaxConcurrency: 2,
		MaxRequests:    5,
		MaxTotalBytes:  4096,
	}
	id, err := store.CreateScope(ctx, sc)
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	if id <= 0 || sc.ID != id {
		t.Fatalf("create scope returned id %d (sc.ID=%d)", id, sc.ID)
	}

	// Uniqueness is enforced with the typed error.
	dup := *sc
	if _, err := store.CreateScope(ctx, &dup); !errors.Is(err, storage.ErrScopeExists) {
		t.Fatalf("duplicate scope: err=%v, want ErrScopeExists", err)
	}

	got, err := store.GetScope(ctx, id)
	if err != nil {
		t.Fatalf("get scope: %v", err)
	}
	if got.Value != "127.0.0.1/32" || len(got.Ports) != 2 || got.Ports[0] != 8080 {
		t.Fatalf("scope round-trip: %+v", got)
	}
	if !got.Active(time.Now().UTC()) {
		t.Fatalf("fresh scope must be active")
	}

	// List keeps history; revoke flips the state.
	list, err := store.ListScopes(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list scopes: %v len=%d", err, len(list))
	}
	revoked, err := store.RevokeScope(ctx, id, time.Now().UTC())
	if err != nil || !revoked {
		t.Fatalf("revoke: %v %v", err, revoked)
	}
	again, err := store.RevokeScope(ctx, id, time.Now().UTC())
	if err != nil || again {
		t.Fatalf("double revoke must report false: %v %v", err, again)
	}
	got2, _ := store.GetScope(ctx, id)
	if got2.RevokedAt == nil || got2.Active(time.Now().UTC()) {
		t.Fatalf("revoked scope must be dead: %+v", got2)
	}

	// Validation is fail-closed on write.
	bad := &storage.Scope{Kind: storage.ScopeKindCIDR, Value: "not-a-cidr", Protocols: []string{"http"}, Ports: []int{80}}
	if _, err := store.CreateScope(ctx, bad); err == nil {
		t.Fatalf("invalid cidr must be refused")
	}
	empty := &storage.Scope{Kind: storage.ScopeKindDomain, Value: "example.com", Protocols: nil, Ports: []int{80}}
	if _, err := store.CreateScope(ctx, empty); err == nil {
		t.Fatalf("a scope permitting no protocol must be refused (default-deny by absence)")
	}

	// ---- append-only audit. ----
	port := 8080
	scopeID := id
	rec := &storage.ScanAudit{
		TargetHost: "127.0.0.1", TargetIP: "127.0.0.1", Port: &port,
		Protocol: "http", Decision: "deny", Reason: "NO_SCOPE", ScopeID: &scopeID,
		Detail: map[string]any{"test": true},
	}
	if err := store.InsertScanAudit(ctx, rec); err != nil {
		t.Fatalf("insert audit: %v", err)
	}
	audits, err := store.ListScanAudits(ctx, 10)
	if err != nil || len(audits) != 1 {
		t.Fatalf("list audits: %v len=%d", err, len(audits))
	}
	if audits[0].Reason != "NO_SCOPE" || audits[0].Detail["test"] != true {
		t.Fatalf("audit round-trip: %+v", audits[0])
	}

	// ---- the additive gseer_app grants from 0018 are in effect. ----
	var hasInsert, hasSelect, hasAuditInsert bool
	if err := pool.QueryRow(ctx,
		`SELECT has_table_privilege('gseer_app','public.scopes','INSERT'),
		        has_table_privilege('gseer_app','public.scopes','SELECT'),
		        has_table_privilege('gseer_app','public.scan_audits','INSERT')`,
	).Scan(&hasInsert, &hasSelect, &hasAuditInsert); err != nil {
		t.Fatalf("privilege check: %v", err)
	}
	if !hasInsert || !hasSelect || !hasAuditInsert {
		t.Fatalf("0018 grants missing: scopes INSERT=%v SELECT=%v scan_audits INSERT=%v",
			hasInsert, hasSelect, hasAuditInsert)
	}
	// And the runtime role still owns nothing (hardened invariant).
	var owns bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		 WHERE n.nspname='public' AND c.relname IN ('scopes','scan_audits') AND c.relowner = (
		     SELECT oid FROM pg_roles WHERE rolname='gseer_app'))`,
	).Scan(&owns); err != nil {
		t.Fatalf("ownership check: %v", err)
	}
	if owns {
		t.Fatalf("gseer_app must not own the active-observation objects")
	}
}
