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

// scope_test.go — the personal engine's scope-registry parity with the
// PostgreSQL engine: same canonical types, same validation, same
// uniqueness/revoke/audit semantics (migration 0002 gives personal mode
// the scopes + scan_audits tables it never had).

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func newScopeTestStore(t *testing.T) *Store {
	t.Helper()
	res, err := Open(filepath.Join(t.TempDir(), "scope-parity.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := NewStore(res.DB)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestScopeRegistryPersonalParity(t *testing.T) {
	ctx := context.Background()
	s := newScopeTestStore(t)

	expires := time.Now().UTC().Add(time.Hour)
	sc := &storage.Scope{
		Kind:        storage.ScopeKindIP,
		Value:       "127.0.0.1",
		Protocols:   []string{"http", "tls"},
		Ports:       []int{8080},
		Note:        "parity",
		ExpiresAt:   &expires,
		MaxRequests: 3,
	}
	id, err := s.CreateScope(ctx, sc)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id <= 0 {
		t.Fatalf("id = %d", id)
	}

	dup := *sc
	if _, err := s.CreateScope(ctx, &dup); !errors.Is(err, ErrScopeExists) {
		t.Fatalf("duplicate: %v, want ErrScopeExists", err)
	}

	got, err := s.GetScope(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Protocols) != 2 || got.Protocols[0] != "http" || len(got.Ports) != 1 {
		t.Fatalf("list round-trip: %+v", got)
	}
	if !got.Active(time.Now().UTC()) {
		t.Fatalf("fresh scope must be active")
	}

	revoked, err := s.RevokeScope(ctx, id, time.Now().UTC())
	if err != nil || !revoked {
		t.Fatalf("revoke: %v %v", err, revoked)
	}
	got2, _ := s.GetScope(ctx, id)
	if got2.RevokedAt == nil || got2.Active(time.Now().UTC()) {
		t.Fatalf("revoked scope must be dead: %+v", got2)
	}

	// A cidr scope canonicalizes through the shared normalizer.
	cidr := &storage.Scope{Kind: storage.ScopeKindCIDR, Value: "127.0.0.1/32", Protocols: []string{"tls"}, Ports: []int{8443}}
	if _, err := s.CreateScope(ctx, cidr); err != nil {
		t.Fatalf("cidr scope: %v", err)
	}

	// Append-only audit + read-back.
	port := 8080
	rec := &storage.ScanAudit{TargetHost: "127.0.0.1", Port: &port, Protocol: "http",
		Decision: "allow", Reason: "", Detail: map[string]any{"run": 1}}
	if err := s.InsertScanAudit(ctx, rec); err != nil {
		t.Fatalf("audit: %v", err)
	}
	audits, err := s.ListScanAudits(ctx, 5)
	if err != nil || len(audits) != 1 {
		t.Fatalf("list audits: %v len=%d", err, len(audits))
	}
	if audits[0].Decision != "allow" || audits[0].Detail["run"] != float64(1) { // JSON numbers decode as float64
		t.Fatalf("audit round-trip: %+v", audits[0])
	}

	// Validation: no-protocol and no-port scopes are refused (default-deny
	// is expressed by ABSENCE of a scope, never by an empty one).
	if _, err := s.CreateScope(ctx, &storage.Scope{Kind: storage.ScopeKindDomain, Value: "example.com", Ports: []int{80}}); err == nil {
		t.Fatalf("empty protocols must be refused")
	}
	if _, err := s.CreateScope(ctx, &storage.Scope{Kind: storage.ScopeKindDomain, Value: "example.com", Protocols: []string{"http"}}); err == nil {
		t.Fatalf("empty ports must be refused")
	}
}
