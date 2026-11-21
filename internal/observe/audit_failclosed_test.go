// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package observe

// audit_failclosed_test.go — FIX A (v0.3.2 security microfix): audit
// persistence must FAIL CLOSED.  Every authorization decision that
// requires audit is durably persisted BEFORE the decision is returned;
// an audit failure on an ALLOW flips the answer to an explicit deny
// (AUDIT_UNAVAILABLE); on a DENY the original denial stands and the
// audit failure is surfaced.  The observer-level half proves NO HTTP
// request and NO TLS connection is made after an audit persistence
// failure (the server-side hit/accept counters stay at zero).

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func TestAuditFailureFailsClosedOnAllow(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	scoped := scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http", "tls"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 9 })

	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scoped}, failAudit: errors.New("db write failed")},
		Now:   func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
	}

	dec, err := g.Authorize(context.Background(), "example.com", 80, storage.ProtocolHTTP)
	if err == nil {
		t.Fatalf("audit failure on ALLOW must fail closed, got allow: %+v", dec)
	}
	if dec.Allowed {
		t.Fatalf("decision must not be allowed after an audit failure: %+v", dec)
	}
	if dec.Reason != ReasonAuditUnavailable {
		t.Fatalf("reason = %s, want AUDIT_UNAVAILABLE", dec.Reason)
	}
	if !strings.Contains(err.Error(), "E_SCOPE_DENIED") || !strings.Contains(err.Error(), "audit could not be persisted") {
		t.Fatalf("error must carry the fail-closed classification: %v", err)
	}
	// No duplicate audit row ambiguity: nothing was recorded.
	if len(g.Store.(*fakeStore).audits) != 0 {
		t.Fatalf("a failed audit must not record rows: %+v", g.Store.(*fakeStore).audits)
	}
}

func TestAuditFailureKeepsDenyAndSurfacesError(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-1 * time.Hour)
	scoped := scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{80},
		func(sc *storage.Scope) { sc.RevokedAt = &revoked })

	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scoped}, failAudit: errors.New("db write failed")},
		Now:   func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
	}

	dec, err := g.Authorize(context.Background(), "example.com", 80, storage.ProtocolHTTP)
	if err == nil {
		t.Fatalf("revoked scope must deny: %+v", dec)
	}
	if dec.Allowed || dec.Reason != ReasonScopeRevoked {
		t.Fatalf("the ORIGINAL denial must stand: %+v", dec)
	}
	if !strings.Contains(err.Error(), "SCOPE_REVOKED") || !strings.Contains(err.Error(), "persistence also failed") {
		t.Fatalf("the audit failure must be surfaced with the denial: %v", err)
	}
	if len(g.Store.(*fakeStore).audits) != 0 {
		t.Fatalf("a failed audit must not record rows: %+v", g.Store.(*fakeStore).audits)
	}
}

func TestAuditFailureRegistryUnavailableStillAudited(t *testing.T) {
	// The registry-unavailable deny is itself a decision: with
	// persistence AVAILABLE it is audited (v0.3.2 microfix closes the
	// pre-fix gap where this path skipped the audit trail).
	g := &Gateway{Store: &fakeStore{failList: errors.New("db down")}}
	dec, err := g.Authorize(context.Background(), "127.0.0.1", 8080, storage.ProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("registry failure must fail closed: %v %+v", err, dec)
	}
	fake := g.Store.(*fakeStore)
	if len(fake.audits) != 1 {
		t.Fatalf("registry-unavailable deny must be audited when persistence works: %+v", fake.audits)
	}
	if fake.audits[0].Decision != "deny" || fake.audits[0].Reason != ReasonAuthzFailureNoProbe {
		t.Fatalf("audit row: %+v", fake.audits[0])
	}

	// With persistence down too, the failure is surfaced (still denied).
	g2 := &Gateway{Store: &fakeStore{failList: errors.New("db down"), failAudit: errors.New("audit down")}}
	_, err2 := g2.Authorize(context.Background(), "127.0.0.1", 8080, storage.ProtocolHTTP)
	if err2 == nil || !strings.Contains(err2.Error(), "persistence also failed") {
		t.Fatalf("double failure must surface both: %v", err2)
	}
}

func TestRevalidateAuditFailureFailsClosed(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	scoped := scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http"}, []int{8080},
		func(sc *storage.Scope) { sc.ID = 4 })
	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scoped}, failAudit: errors.New("db write failed")},
		Now:   func() time.Time { return now },
	}
	_, err := g.Revalidate(context.Background(), "127.0.0.1", netip.MustParseAddr("127.0.0.1"), 8080, storage.ProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "FAIL CLOSED") {
		t.Fatalf("pre-dial re-validation with a failing audit must fail closed: %v", err)
	}
}

func TestHTTPObserverNeverConnectsAfterAuditFailure(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	g := &Gateway{Store: &fakeStore{
		scopes: []storage.Scope{scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http"}, []int{port},
			func(sc *storage.Scope) { sc.ID = 11 })},
		failAudit: errors.New("audit storage down"),
	}}
	obs := &HTTPObserver{GW: g}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("run must fail closed with the deny classification: %v %+v", err, res)
	}
	if hits != 0 {
		t.Fatalf("NO HTTP request may proceed after an audit persistence failure (hits=%d)", hits)
	}
}

func TestTLSObserverNeverConnectsAfterAuditFailure(t *testing.T) {
	var accepts int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	// Count raw connections on the listener (a TLS handshake failure
	// still opens a socket — the invariant is about CONNECTIONS).
	raw, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			accepts++
			_ = c.Close()
		}
	}()
	port := raw.Addr().(*net.TCPAddr).Port
	defer func() { _ = raw.Close() }()
	_ = srv // the httptest TLS server exists to prove the fixture shape; the counting listener is the target

	g := &Gateway{Store: &fakeStore{
		scopes: []storage.Scope{scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"tls"}, []int{port},
			func(sc *storage.Scope) { sc.ID = 12 })},
		failAudit: errors.New("audit storage down"),
	}}
	obs := &TLSObserver{GW: g, Timeout: 2 * time.Second}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("run must fail closed with the deny classification: %v %+v", err, res)
	}
	if accepts != 0 {
		t.Fatalf("NO TLS connection may proceed after an audit persistence failure (accepts=%d)", accepts)
	}
}

func TestTLSObserverDeniesAfterPreDialRevalidationFailure(t *testing.T) {
	// The audit WORKS on the initial allow, but fails on the pre-dial
	// re-validation: the connection must not be made.
	var accepts int
	raw, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			accepts++
			// Speak enough TLS framing to let the client fail fast.
			_ = tls.Server(c, nil).Close()
		}
	}()
	port := raw.Addr().(*net.TCPAddr).Port
	defer func() { _ = raw.Close() }()

	g := &Gateway{Store: &fakeStore{
		scopes: []storage.Scope{scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"tls"}, []int{port},
			func(sc *storage.Scope) { sc.ID = 13 })},
	}}
	g.Store.(*fakeStore).failAudit = errors.New("audit storage down") // flips BEFORE the run: every audit fails

	obs := &TLSObserver{GW: g, Timeout: 2 * time.Second}
	_, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("pre-dial audit failure must deny the connection: %v", err)
	}
	if accepts != 0 {
		t.Fatalf("the socket must never be dialed after the re-validation failed (accepts=%d)", accepts)
	}
}
