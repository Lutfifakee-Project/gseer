// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package observe

// domain_revalidation_test.go — FINAL-security-microfix FIX A: the
// pre-dial re-validation is DOMAIN-AWARE.  The pre-fix Revalidate
// re-wrote the decision's hostname to the pinned IP's text, which
// (a) denied validly-scoped domain/domain_suffix targets at the
// pre-dial gate and (b) stopped re-testing the hostname's scope
// permissions entirely.
//
// Two proof layers:
//  1. GATEWAY-LEVEL (strict, no dial): domain/suffix matching, suffix
//     label boundaries, revocation/expiry, protocol/port re-checks and
//     the address policy are exercised against the CURRENT registry
//     with a TEST-NET-3 pinned address (RFC 5737 — never dialed; no
//     packet leaves the sandbox).
//  2. END-TO-END (loopback servers): the operator-realistic scope pair
//     (domain scope for the name + loopback CIDR for the restricted
//     address) proves the wiring — allowed runs, redirect re-checks,
//     single-resolution rebinding protection and the fail-closed
//     registry/audit gates.  Deny-at-connection tests revoke BOTH
//     scopes so the answer cannot come from a surviving scope.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// testNetIP is a TEST-NET-3 address (RFC 5737, guaranteed
// non-assignable): used ONLY for gateway-level decisions — it is never
// dialed, so no packet ever leaves the sandbox.
var testNetIP = netip.MustParseAddr("203.0.113.10")

func loopbackLookup() func(ctx context.Context, host string) ([]netip.Addr, error) {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
}

// ---------------------------------------------------------------------------
// 1. Gateway-level proofs (no dial; TEST-NET-3 pinned address).
// ---------------------------------------------------------------------------

func TestRevalidateDomainScopeAllowed(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	sc := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 71 })
	g := &Gateway{
		Store:    &fakeStore{scopes: []storage.Scope{sc}},
		Now:      func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) { return []netip.Addr{testNetIP}, nil },
	}

	// The FIX A proof: re-validating the ORIGINAL hostname + the pinned
	// address must match the domain scope.  The pre-fix signature
	// (IP-only) re-wrote the hostname and returned NO_SCOPE here.
	dec, err := g.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP)
	if err != nil || !dec.Allowed {
		t.Fatalf("FIX A regression: pre-dial re-validation must keep the domain scope match: err=%v dec=%+v", err, dec)
	}
	if dec.Scope == nil || dec.Scope.Kind != storage.ScopeKindDomain {
		t.Fatalf("the acting scope must remain the DOMAIN scope: %+v", dec)
	}
	if dec.IP != testNetIP {
		t.Fatalf("the pinned address must be carried unchanged: %+v", dec)
	}
	// The authorization path agrees (same matching semantics).
	if dec2, aerr := g.Authorize(context.Background(), "myserver.test", 80, storage.ProtocolHTTP); aerr != nil || !dec2.Allowed {
		t.Fatalf("authorize must allow the domain target: %v %+v", aerr, dec2)
	}
}

func TestRevalidateDomainSuffixBoundary(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	sc := scopeAt(storage.ScopeKindDomainSuffix, "example.test", []string{"http"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 72 })
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}}, Now: func() time.Time { return now }}

	// Real subdomain: allowed at re-validation.
	if dec, err := g.Revalidate(context.Background(), "shop.example.test", testNetIP, 80, storage.ProtocolHTTP); err != nil || !dec.Allowed {
		t.Fatalf("suffix must allow its subdomains at re-validation: %v %+v", err, dec)
	}
	// Fake-tail host: "example.test" is NOT a suffix of
	// "example.com.attacker.test" — the boundary must hold at
	// re-validation exactly as at authorization.
	dec, err := g.Revalidate(context.Background(), "example.com.attacker.test", testNetIP, 80, storage.ProtocolHTTP)
	if err == nil || dec.Allowed || dec.Reason != ReasonNoScope {
		t.Fatalf("fake-tail host must be denied with NO_SCOPE at re-validation: %v %+v", err, dec)
	}
	// Superstring host: "notexample.test" does not end with
	// ".example.test" (label boundary).
	if dec, err := g.Revalidate(context.Background(), "notexample.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || dec.Allowed {
		t.Fatalf("superstring host must be denied (label boundary): %v %+v", err, dec)
	}
	// The bare suffix itself IS covered (name == suffix is part of the
	// suffix contract — the same rule Authorize applies).
	if dec, err := g.Revalidate(context.Background(), "example.test", testNetIP, 80, storage.ProtocolHTTP); err != nil || !dec.Allowed {
		t.Fatalf("bare suffix host must match a suffix scope (name==suffix rule): %v %+v", err, dec)
	}
}

func TestRevalidateDomainScopeRevokedExpiredAndMismatched(t *testing.T) {
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	sc := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 73 })

	// Revoked between authorization and dial: the pre-dial re-validation
	// denies (the row exists but is dead).
	revoked := now.Add(-time.Second)
	dead := sc
	dead.RevokedAt = &revoked
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{dead}}, Now: func() time.Time { return now }}
	if dec, err := g.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || dec.Allowed || dec.Reason != ReasonScopeRevoked {
		t.Fatalf("revoked domain scope must deny at re-validation: %v %+v", err, dec)
	}

	// Expired: the same fail-closed answer.
	expired := now.Add(-time.Second)
	dead2 := sc
	dead2.ExpiresAt = &expired
	g2 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{dead2}}, Now: func() time.Time { return now }}
	if dec, err := g2.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || dec.Allowed || dec.Reason != ReasonScopeExpired {
		t.Fatalf("expired domain scope must deny at re-validation: %v %+v", err, dec)
	}

	// Protocol re-check: the scope lists tls only; the http re-validation
	// denies (the pre-fix IP-only path skipped this check entirely).
	scTLS := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"tls"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 74 })
	g3 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{scTLS}}, Now: func() time.Time { return now }}
	if dec, err := g3.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || dec.Reason != ReasonProtocolNotPermitted {
		t.Fatalf("protocol mismatch must deny at re-validation: %v %+v", err, dec)
	}

	// Port re-check: the scope lists 8443 only.
	scPort := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{8443},
		func(sc *storage.Scope) { sc.ID = 75 })
	g4 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{scPort}}, Now: func() time.Time { return now }}
	if dec, err := g4.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || dec.Reason != ReasonPortNotPermitted {
		t.Fatalf("port mismatch must deny at re-validation: %v %+v", err, dec)
	}

	// Address policy on the PIN: the name is scoped, but the pinned
	// address is restricted (loopback) with no address-level scope —
	// the destination policy denies even though the hostname matches.
	g5 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}}, Now: func() time.Time { return now }}
	if dec, err := g5.Revalidate(context.Background(), "myserver.test", netip.MustParseAddr("127.0.0.1"), 80, storage.ProtocolHTTP); err == nil || dec.Reason != ReasonPrivateUnscoped {
		t.Fatalf("restricted pinned address must deny despite the hostname scope: %v %+v", err, dec)
	}

	// Registry failure at re-validation: fail-closed.
	g6 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}, failList: errors.New("db down")}, Now: func() time.Time { return now }}
	if dec, err := g6.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("registry failure at re-validation must fail closed: %v %+v", err, dec)
	}

	// Audit failure at re-validation: fail-closed, no connection.
	g7 := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}, failAudit: errors.New("audit down")}, Now: func() time.Time { return now }}
	if _, err := g7.Revalidate(context.Background(), "myserver.test", testNetIP, 80, storage.ProtocolHTTP); err == nil || !strings.Contains(err.Error(), "AUDIT_UNAVAILABLE") {
		t.Fatalf("audit failure at re-validation must fail closed: %v", err)
	}
}

func TestAuthorizeDomainScopeIsNotAnIPScope(t *testing.T) {
	// FIX A boundary: the domain scope must not silently become an IP
	// scope — an IP-literal target that merely echoes the scoped
	// hostname's address is NOT covered by a domain scope (host
	// matching is name-based; the ip/cidr kinds cover addresses).
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	sc := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{80},
		func(sc *storage.Scope) { sc.ID = 76 })
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}}, Now: func() time.Time { return now }}
	if dec, err := g.Authorize(context.Background(), "203.0.113.10", 80, storage.ProtocolHTTP); err == nil || dec.Allowed || dec.Reason != ReasonNoScope {
		t.Fatalf("a bare IP target must NOT match a domain scope: %v %+v", err, dec)
	}
}

// ---------------------------------------------------------------------------
// 2. End-to-end proofs on loopback servers (operator-realistic scope
//    pair: the domain scope authorizes the name; the loopback CIDR
//    satisfies the restricted-address policy).
// ---------------------------------------------------------------------------

// dualScopeGateway builds the e2e registry: the name scope + the
// loopback scope, with the optional per-ListScopes hook.
func dualScopeGateway(nameScope, loopScope storage.Scope, hook func(call int)) *Gateway {
	fs := &fakeStore{scopes: []storage.Scope{nameScope, loopScope}}
	fs.listHook = hook
	return &Gateway{Store: fs, LookupIP: loopbackLookup()}
}

func TestDomainScopeAllowedEndToEnd(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		fmt.Fprint(w, "<html><title>Domain Target</title>ok</html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 31; sc.MaxRequests = 3 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 311 })
	g := dualScopeGateway(name, loop, nil)
	fs := g.Store.(*fakeStore)
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err != nil || !res.OK {
		t.Fatalf("FIX A regression: a domain-scoped run must survive the pre-dial re-validation: err=%v res=%+v (listCalls=%d)", err, res, fs.listCalls)
	}
	if gotHost != "myserver.test" {
		t.Fatalf("virtual-hosting must carry the original hostname, got %q", gotHost)
	}
	if fs.listCalls < 3 {
		t.Fatalf("the run must re-check the registry (initial + hop + pre-dial), got %d calls", fs.listCalls)
	}
}

func TestTLSWithDomainScopeAllowed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port := atoiOrFatal(t, portStr)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"tls"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 32 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"tls"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 321 })
	g := dualScopeGateway(name, loop, nil)
	obs := &TLSObserver{GW: g, Timeout: 3 * time.Second}

	// The httptest cert does not match the name and is self-signed —
	// capture-not-verify: the handshake itself must SUCCEED.
	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err != nil {
		t.Fatalf("FIX A regression: TLS run under a domain scope failed: %v (%+v)", err, res)
	}
	if !res.OK {
		t.Fatalf("TLS observation reported failure: %s", res.Failure)
	}
}

func TestDomainSuffixScopeAllowedEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	port := srvPort(t, srv)

	suffix := scopeAt(storage.ScopeKindDomainSuffix, "example.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 33 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 331 })
	g := dualScopeGateway(suffix, loop, nil)
	obs := &HTTPObserver{GW: g}

	if res, err := obs.Run(context.Background(), "shop.example.test", port); err != nil || !res.OK {
		t.Fatalf("suffix scope must allow its subdomains end-to-end: err=%v res=%+v", err, res)
	}
}

func TestDomainScopeRevokedBeforeConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 34 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 341 })
	// Calls #1 (initial) pass; every NEW-connection re-check (#2+) sees
	// BOTH scopes revoked — no surviving scope can carry the dial.
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	fs.listHook = func(call int) {
		if call >= 2 {
			rev := time.Now().UTC().Add(-time.Second)
			for i := range fs.scopes {
				fs.scopes[i].RevokedAt = &rev
			}
		}
	}
	g := &Gateway{Store: fs, LookupIP: loopbackLookup()}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err == nil || !strings.Contains(err.Error(), "SCOPE_REVOKED") {
		t.Fatalf("revoked scopes must deny before the first dial: %v %+v", err, res)
	}
	if hits != 0 {
		t.Fatalf("no connection after revocation (hits=%d)", hits)
	}
}

func TestTLSWithDomainScopeRevokedBeforeDial(t *testing.T) {
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
			_ = tls.Server(c, nil).Close()
		}
	}()
	port := raw.Addr().(*net.TCPAddr).Port
	defer func() { _ = raw.Close() }()

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"tls"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 35 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"tls"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 351 })
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	fs.listHook = func(call int) {
		if call >= 2 { // call #2 = the pre-dial re-validation
			rev := time.Now().UTC().Add(-time.Second)
			for i := range fs.scopes {
				fs.scopes[i].RevokedAt = &rev
			}
		}
	}
	g := &Gateway{Store: fs, LookupIP: loopbackLookup()}
	obs := &TLSObserver{GW: g, Timeout: 2 * time.Second}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err == nil || !strings.Contains(err.Error(), "SCOPE_REVOKED") {
		t.Fatalf("revoked scopes must deny the TLS dial: %v %+v", err, res)
	}
	if accepts != 0 {
		t.Fatalf("no TLS connection after revocation (accepts=%d)", accepts)
	}
}

func TestDomainScopeExpiredBeforeConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	base := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	var calls int32
	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) {
			sc.ID = 36
			exp := base.Add(time.Second)
			sc.ExpiresAt = &exp
		})
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) {
			sc.ID = 361
			exp := base.Add(time.Second)
			sc.ExpiresAt = &exp
		})
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	g := &Gateway{
		Store:    fs,
		LookupIP: loopbackLookup(),
		Now: func() time.Time {
			n := atomic.AddInt32(&calls, 1)
			return base.Add(time.Duration(n-1) * 2 * time.Second) // every gateway call advances 2s
		},
	}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err == nil || !strings.Contains(err.Error(), "SCOPE_EXPIRED") {
		t.Fatalf("expired scopes must deny before the first dial: %v %+v", err, res)
	}
	if hits != 0 {
		t.Fatalf("no connection after expiry (hits=%d)", hits)
	}
}

func TestPinnedIPNotCoveredByScopesDenied(t *testing.T) {
	// The name scope + loopback scope authorize the usual target, but
	// the DNS double points the name at a DIFFERENT private address:
	// the destination policy denies (the pinned address is what counts).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "internal.example", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 39 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 391 })
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	g := &Gateway{
		Store: fs,
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.1.2.3")}, nil // private, unscoped
		},
	}
	obs := &HTTPObserver{GW: g}
	if _, err := obs.Run(context.Background(), "internal.example", port); err == nil ||
		!strings.Contains(err.Error(), ReasonPrivateUnscoped) {
		t.Fatalf("pinned private address outside every scope must deny: %v", err)
	}
}

func TestRedirectToUnpermittedDomainDenied(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/" {
			w.Header().Set("Location", "http://evil.test/away")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "should never be reached")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 40; sc.MaxRequests = 3 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 401 })
	g := dualScopeGateway(name, loop, nil)
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, "redirect hop denied") {
		t.Fatalf("the unpermitted redirect domain must be denied: %+v", res)
	}
	if hits != 1 {
		t.Fatalf("the redirect target must never be contacted (hits=%d)", hits)
	}
}

func TestDNSRebindingAttemptKeepsPinnedIPAndSingleResolution(t *testing.T) {
	// The attacker's DNS alternates addresses; the gateway must resolve
	// ONCE (at authorization), pin that address, use it for the
	// connection, and NEVER re-resolve for re-validation.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, "<html><title>Pinned</title></html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "victim.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 41 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 411 })
	var lookups int32
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	g := &Gateway{
		Store: fs,
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			n := atomic.AddInt32(&lookups, 1)
			if n <= 2 {
				// The two LEGITIMATE resolutions: the initial
				// authorization and the hop-0 re-authorization — both
				// gateway-owned, both validated against the registry
				// before anything dials.
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			// A "rebinding" third answer — if re-validation ever
			// re-resolved behind the gateway, this would fire and the
			// test's lookup-count assertion would catch it.
			return []netip.Addr{netip.MustParseAddr("127.0.0.99")}, nil
		},
	}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "victim.test", port)
	if err != nil || !res.OK {
		t.Fatalf("the pinned connection must succeed: err=%v res=%+v", err, res)
	}
	if n := atomic.LoadInt32(&lookups); n != 2 {
		t.Fatalf("exactly the two gateway-owned resolutions are allowed (got %d) — re-validation never re-resolves", n)
	}
	if hits != 1 {
		t.Fatalf("exactly one connection, to the pinned address (hits=%d)", hits)
	}
}

func TestDomainRevalidationRegistryFailureDeniedNoConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 42 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 421 })
	// Calls #1..#2 pass; the PRE-DIAL re-validation (#3) sees a dead
	// registry — fail-closed, nothing connects.
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	fs.listHook = func(call int) {
		if call >= 3 {
			fs.failList = errors.New("registry down")
		}
	}
	g := &Gateway{Store: fs, LookupIP: loopbackLookup()}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err != nil {
		t.Fatalf("a pre-dial registry failure is an observation OF FAILURE: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, "fail-closed") {
		t.Fatalf("the pre-dial registry failure must deny the dial: %+v", res)
	}
	if hits != 0 {
		t.Fatalf("no connection may be made while the registry is unavailable (hits=%d)", hits)
	}
}

func TestDomainRevalidationAuditFailureDeniedNoConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	name := scopeAt(storage.ScopeKindDomain, "myserver.test", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 43 })
	loop := scopeAt(storage.ScopeKindCIDR, "127.0.0.1/32", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 431 })
	// The audit works for the planning decisions but fails for the
	// pre-dial re-validation (#3): nothing may connect.
	fs := &fakeStore{scopes: []storage.Scope{name, loop}}
	fs.listHook = func(call int) {
		if call >= 3 {
			fs.failAudit = errors.New("audit storage down")
		}
	}
	g := &Gateway{Store: fs, LookupIP: loopbackLookup()}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "myserver.test", port)
	if err != nil {
		t.Fatalf("a pre-dial audit failure is an observation OF FAILURE: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, "AUDIT_UNAVAILABLE") {
		t.Fatalf("the un-auditable pre-dial allow must fail closed: %+v", res)
	}
	if hits != 0 {
		t.Fatalf("no connection after an audit persistence failure (hits=%d)", hits)
	}
}

// atoiOrFatal is the test-side port parser for the TLS server URL.
func atoiOrFatal(t *testing.T, s string) int {
	t.Helper()
	p := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("bad port %q", s)
		}
		p = p*10 + int(c-'0')
	}
	return p
}
