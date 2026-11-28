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

package observe

// revalidation_test.go — FIX B (v0.3.2 security microfix): authorization
// is re-checked immediately before EVERY connection.  The revocation
// timing is simulated with deterministic test doubles (the fakeStore's
// listHook flips the registry on the Nth ListScopes call) — no external
// target is ever contacted: every "server" is a loopback httptest
// listener explicitly covered by an operator scope.
//
// Call-order contract proven here (one HTTP run = 3 registry reads
// minimum):
//
//	#1  the initial Authorize (planning: source row, limits, res fields)
//	#2  the hop-0 re-Authorize (immediately before the first request)
//	#3  the DialContext Revalidate (immediately before the socket)
//
// with one more (#4+) per redirect hop.  The TLS observer is #1 then
// the pre-dial Revalidate.

import (
	"context"
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

// loopbackScope builds the operator scope authorizing exactly the
// loopback address on the given port.
func loopbackScope(port int, mut func(*storage.Scope)) storage.Scope {
	return scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http", "tls"}, []int{port},
		func(sc *storage.Scope) {
			sc.ID = 21
			sc.MaxRequests = 6
			if mut != nil {
				mut(sc)
			}
		})
}

func TestScopeRevokedBeforeFirstDialHTTP(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	sc := loopbackScope(port, nil)
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	// Call #1 (initial authorize) sees the live scope; every later read
	// (#2 = the hop-0 re-Authorize) sees it revoked.
	fs.listHook = func(call int) {
		if call >= 2 {
			rev := time.Now().UTC().Add(-time.Second)
			fs.scopes[0].RevokedAt = &rev
		}
	}
	g := &Gateway{Store: fs}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("revocation before the first dial must deny the run: %v %+v", err, res)
	}
	if hits != 0 {
		t.Fatalf("no connection may be made after revocation (hits=%d)", hits)
	}
}

func TestScopeRevokedAtPreDialRevalidationHTTP(t *testing.T) {
	// The hop-0 re-Authorize (#2) still passes; ONLY the pre-dial
	// Revalidate (#3) sees the revocation — the dial must be refused
	// with nothing recorded as a complete response.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	sc := loopbackScope(port, nil)
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	fs.listHook = func(call int) {
		if call >= 3 {
			rev := time.Now().UTC().Add(-time.Second)
			fs.scopes[0].RevokedAt = &rev
		}
	}
	g := &Gateway{Store: fs}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("a pre-dial denial is an observation OF FAILURE (recorded, not a run error): %v", err)
	}
	if res.OK {
		t.Fatalf("the run must NOT report a complete response: %+v", res)
	}
	if !strings.Contains(res.Failure, "SCOPE_REVOKED") || !strings.Contains(res.Failure, "pre-dial re-validation") {
		t.Fatalf("failure must name the pre-dial denial: %s", res.Failure)
	}
	if hits != 0 {
		t.Fatalf("the pre-dial re-validation must prevent the connection (hits=%d)", hits)
	}
}

func TestScopeExpiresBeforeFirstDialHTTP(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	base := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	var calls int32
	sc := loopbackScope(port, nil)
	exp := base.Add(time.Second)
	sc.ExpiresAt = &exp
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	// Every gateway call advances the injectable clock by 2s: call #1
	// (initial) is inside the validity window, call #2 (hop-0 re-check)
	// is past the expiry.
	g := &Gateway{
		Store: fs,
		Now: func() time.Time {
			n := atomic.AddInt32(&calls, 1)
			return base.Add(time.Duration(n-1) * 2 * time.Second)
		},
	}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") || !strings.Contains(err.Error(), "SCOPE_EXPIRED") {
		t.Fatalf("expiry before the first dial must deny: %v %+v", err, res)
	}
	if hits != 0 {
		t.Fatalf("no connection after expiry (hits=%d)", hits)
	}
}

func TestScopeRevokedBetweenRedirectHops(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><title>Final</title></html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	sc := loopbackScope(port, nil)
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	// Calls #1..#3 (initial, hop-0, hop-0 dial revalidation) pass; the
	// hop-1 Authorize (#4) sees the revocation.
	fs.listHook = func(call int) {
		if call >= 4 {
			rev := time.Now().UTC().Add(-time.Second)
			fs.scopes[0].RevokedAt = &rev
		}
	}
	g := &Gateway{Store: fs}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("a denied redirect hop ends the chain honestly (no run error): %v", err)
	}
	if res.OK {
		t.Fatalf("the chain must not report a complete response: %+v", res)
	}
	joined := strings.Join(res.Redirects, " | ")
	if !strings.Contains(joined, "DENIED") || !strings.Contains(res.Failure, "redirect hop denied") {
		t.Fatalf("the denied hop must be recorded: %v / %s", res.Redirects, res.Failure)
	}
	if hits != 1 {
		t.Fatalf("only the first hop may connect (hits=%d)", hits)
	}
}

func TestRedirectToOutOfScopeHostDenied(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "http://other.example/away")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{loopbackScope(port, nil)}}}
	obs := &HTTPObserver{GW: g}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, "redirect hop denied") {
		t.Fatalf("out-of-scope redirect must be denied: %+v", res)
	}
	if hits != 1 {
		t.Fatalf("the unapproved target must never be contacted (hits=%d)", hits)
	}
}

func TestRedirectToPrivateIPWithoutExplicitScopeDenied(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "http://10.0.0.5/private")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	// The scope authorizes ONLY the loopback address — the RFC1918
	// redirect target has no address-level scope: PRIVATE_UNSCOPED.
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{loopbackScope(port, nil)}}}
	obs := &HTTPObserver{GW: g}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, ReasonPrivateUnscoped) {
		t.Fatalf("private redirect target must be denied with %s: %+v", ReasonPrivateUnscoped, res)
	}
	if hits != 1 {
		t.Fatalf("the private target must never be contacted (hits=%d)", hits)
	}
}

func TestRedirectToUnresolvableHostDenied(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "http://gone.example/nowhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{loopbackScope(port, nil)}}}
	g.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return nil, errors.New("NXDOMAIN")
	}
	obs := &HTTPObserver{GW: g}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, ReasonDNSNoAnswer) {
		t.Fatalf("unresolvable redirect target must fail closed with %s: %+v", ReasonDNSNoAnswer, res)
	}
	if hits != 1 {
		t.Fatalf("nothing may probe the unresolvable target (hits=%d)", hits)
	}
}

func TestReconnectAfterRevocationDenied(t *testing.T) {
	// Two sequential runs over the same observer: the scope is revoked
	// between them — the second run's FIRST re-authorization denies, so
	// the "reconnect" never touches the network.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	port := srvPort(t, srv)

	sc := loopbackScope(port, nil)
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}}}
	obs := &HTTPObserver{GW: g}

	res1, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil || !res1.OK {
		t.Fatalf("first run must succeed: %v %+v", err, res1)
	}
	rev := time.Now().UTC().Add(-time.Second)
	g.Store.(*fakeStore).scopes[0].RevokedAt = &rev

	_, err = obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "SCOPE_REVOKED") {
		t.Fatalf("the reconnect after revocation must be denied: %v", err)
	}
	if hits != 1 {
		t.Fatalf("the revoked reconnect must not connect (hits=%d)", hits)
	}
}

func TestGatewayLookupFailureBeforeDialDenied(t *testing.T) {
	// Gateway.Revalidate itself fails closed when the registry is
	// unavailable (no connection can be built on a dead registry).
	sc := loopbackScope(8080, nil)
	g := &Gateway{Store: &fakeStore{scopes: []storage.Scope{sc}, failList: errors.New("db down")}}
	_, err := g.Revalidate(context.Background(), "127.0.0.1", netip.MustParseAddr("127.0.0.1"), 8080, storage.ProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("pre-dial re-validation on a dead registry must fail closed: %v", err)
	}
}

func TestRevalidateDeniesUnscopedPrivateAddress(t *testing.T) {
	// The pin is authoritative: revalidating an address the scope does
	// NOT cover (private range, no address-level scope) denies — the
	// dialer can never be talked into a different destination.
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{loopbackScope(8080, nil)}},
		Now:   func() time.Time { return now },
	}
	dec, err := g.Revalidate(context.Background(), "10.1.2.3", netip.MustParseAddr("10.1.2.3"), 8080, storage.ProtocolHTTP)
	if err == nil || dec.Allowed || dec.Reason != ReasonPrivateUnscoped {
		t.Fatalf("revalidation of an unscoped private address must deny: %v %+v", err, dec)
	}
}

func TestDialContextRefusesUnpinnedAddress(t *testing.T) {
	// Belt-and-braces: even if some future code path built a URL with a
	// different host, the dialer refuses any address but the pin.
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{loopbackScope(8080, nil)}},
		Now:   func() time.Time { return now },
	}
	o := &HTTPObserver{GW: g}
	client := o.clientFor(g, nil, "127.0.0.1", netip.MustParseAddr("127.0.0.1"), 8080, "http", time.Second)
	_, err := client.Get("http://198.51.100.7:8080/")
	if err == nil || !strings.Contains(err.Error(), "not the gateway-validated address") {
		t.Fatalf("the dialer must refuse a non-pinned destination: %v", err)
	}
}

func TestTLSObserverDeniesRevocationBeforeDial(t *testing.T) {
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
			_ = c.Close()
		}
	}()
	port := raw.Addr().(*net.TCPAddr).Port
	defer func() { _ = raw.Close() }()

	sc := loopbackScope(port, nil)
	sc.Protocols = []string{"tls"}
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	// Call #1 (initial authorize) passes; call #2 (the pre-dial
	// Revalidate) sees the revocation.
	fs.listHook = func(call int) {
		if call >= 2 {
			rev := time.Now().UTC().Add(-time.Second)
			fs.scopes[0].RevokedAt = &rev
		}
	}
	g := &Gateway{Store: fs}
	obs := &TLSObserver{GW: g, Timeout: 2 * time.Second}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "SCOPE_REVOKED") {
		t.Fatalf("revocation before the TLS dial must deny: %v %+v", err, res)
	}
	if accepts != 0 {
		t.Fatalf("no TLS connection may be made after revocation (accepts=%d)", accepts)
	}
}
