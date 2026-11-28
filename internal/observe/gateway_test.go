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

// gateway_test.go — the default-deny authorization matrix.  Every deny
// row of the gateway contract is pinned here against a FAKE store (no
// database): missing scope, revoked, expired, deny-mode, protocol
// mismatch, port mismatch, unscoped private address, DNS-no-answer,
// plus the allow path, the audited trail, suffix/ CIDR matching and the
// rebinding address pin.  The observers' end-to-end behavior lives in
// observe_e2e_test.go (real HTTP/TLS servers + the personal SQLite
// engine).

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// fakeStore is the observe.Store fake: scopes + an audit trail in
// memory (no DB, no network).
type fakeStore struct {
	scopes []storage.Scope
	audits []storage.ScanAudit
	// failList scopes the ListScopes failure (fail-closed check).
	failList error
	// failAudit scopes the InsertScanAudit failure (FIX A fail-closed
	// checks).  A failed audit records NOTHING (like a real failed
	// insert — no duplicate-row ambiguity).
	failAudit error
	// heldLeases simulates the cross-process lease slots (token-keyed,
	// like the real engines): acquire appends a fresh token, release and
	// renewal match the token exactly — an old holder can never touch a
	// newer holder's lease (final-security-microfix FIX B).
	heldLeases map[int64][]string
	// renewErr scopes RenewScanLease failure (renewal fail-closed
	// checks); renewCalls counts renewals (atomic: the heartbeat
	// goroutine increments it while tests read it concurrently).
	renewErr   error
	renewCalls atomic.Int64
	// auditDelay slows InsertScanAudit — the deterministic seam that
	// opens a window between the pre-dial authorization and the dial
	// (for the lease-lost gate tests).
	auditDelay time.Duration
	// listHook (optional) runs before each ListScopes return with the
	// 1-based call number — the revocation-timing test seam (FIX B).
	listHook func(call int)
	// listCalls counts ListScopes invocations.
	listCalls int
}

func (f *fakeStore) ListScopes(ctx context.Context) ([]storage.Scope, error) {
	f.listCalls++
	if f.listHook != nil {
		f.listHook(f.listCalls)
	}
	if f.failList != nil {
		return nil, f.failList
	}
	return f.scopes, nil
}

func (f *fakeStore) InsertScanAudit(ctx context.Context, rec *storage.ScanAudit) error {
	if f.failAudit != nil {
		return f.failAudit
	}
	if f.auditDelay > 0 {
		time.Sleep(f.auditDelay)
	}
	f.audits = append(f.audits, *rec)
	return nil
}

func (f *fakeStore) EnsureSource(ctx context.Context, name, connector, termsRef string, cfg map[string]any) (int64, error) {
	return 1, nil
}

func (f *fakeStore) IngestFacts(ctx context.Context, facts []storage.Fact) (storage.IngestStats, error) {
	return storage.IngestStats{}, nil
}

// AcquireScanLease / RenewScanLease / ReleaseScanLease — the in-memory
// lease simulation with token ownership (the real engines' contract
// lives in the storage packages' tests).
func (f *fakeStore) AcquireScanLease(ctx context.Context, scopeID int64, maxConcurrency int, ttl time.Duration, holder string) (*storage.ScanLease, error) {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	if f.heldLeases == nil {
		f.heldLeases = map[int64][]string{}
	}
	if len(f.heldLeases[scopeID]) >= maxConcurrency {
		return nil, fmt.Errorf("E_SCOPE_BUSY: fake: scope %d busy: %w", scopeID, storage.ErrScopeBusy)
	}
	token, terr := storage.NewLeaseToken()
	if terr != nil {
		return nil, terr
	}
	f.heldLeases[scopeID] = append(f.heldLeases[scopeID], token)
	now := time.Now().UTC()
	return &storage.ScanLease{
		ScopeID:    scopeID,
		Slot:       len(f.heldLeases[scopeID]),
		Holder:     holder,
		Token:      token,
		AcquiredAt: now,
		ExpiresAt:  now.Add(ttl),
	}, nil
}

func (f *fakeStore) RenewScanLease(ctx context.Context, lease *storage.ScanLease, ttl time.Duration) error {
	f.renewCalls.Add(1)
	if f.renewErr != nil {
		return f.renewErr
	}
	if lease == nil || !f.holdsToken(lease.ScopeID, lease.Token) {
		return fmt.Errorf("E_SCOPE_BUSY: fake: lease token not held: %w", storage.ErrLeaseLost)
	}
	lease.ExpiresAt = time.Now().UTC().Add(ttl)
	return nil
}

func (f *fakeStore) ReleaseScanLease(ctx context.Context, lease *storage.ScanLease) error {
	if lease == nil || f.heldLeases == nil {
		return nil
	}
	tokens := f.heldLeases[lease.ScopeID]
	for i, tok := range tokens {
		if tok == lease.Token {
			f.heldLeases[lease.ScopeID] = append(tokens[:i], tokens[i+1:]...)
			return nil
		}
	}
	return nil // not ours (stolen/released) — token-scoped no-op
}

func (f *fakeStore) holdsToken(scopeID int64, token string) bool {
	for _, tok := range f.heldLeases[scopeID] {
		if tok == token {
			return true
		}
	}
	return false
}

// scopeAt builds one allow-scope with the common boilerplate filled.
func scopeAt(kind storage.ScopeKind, value string, protocols []string, ports []int, mut func(*storage.Scope)) storage.Scope {
	sc := storage.Scope{
		ID:             int64(len(kind) + len(value)),
		Kind:           kind,
		Value:          value,
		Mode:           "allow",
		Protocols:      protocols,
		Ports:          ports,
		MaxConcurrency: 1,
		MaxRequests:    3,
	}
	if mut != nil {
		mut(&sc)
	}
	return sc
}

// denyOf runs Authorize and extracts (decision, error) with the
// invariant that a deny NEVER probes and ALWAYS audits.
func denyOf(t *testing.T, g *Gateway, host string, port int, proto storage.ScopeProtocol) (*Decision, error) {
	t.Helper()
	dec, err := g.Authorize(context.Background(), host, port, proto)
	if err == nil {
		t.Fatalf("expected deny, got allow: %+v", dec)
	}
	if dec.Allowed {
		t.Fatalf("decision claims allowed despite the error: %+v", dec)
	}
	if dec.Reason == "" {
		t.Fatalf("deny carries no reason code: %+v", dec)
	}
	if len(g.Store.(*fakeStore).audits) == 0 {
		t.Fatalf("deny was not audited")
	}
	last := g.Store.(*fakeStore).audits[len(g.Store.(*fakeStore).audits)-1]
	if last.Decision != "deny" || last.Reason != dec.Reason {
		t.Fatalf("audit row mismatch: row(decision=%s reason=%s) vs decision(reason=%s)", last.Decision, last.Reason, dec.Reason)
	}
	return dec, err
}

func TestGatewayDefaultDenyMatrix(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	newGW := func(scopes ...storage.Scope) *Gateway {
		return &Gateway{
			Store: &fakeStore{scopes: scopes},
			Now:   func() time.Time { return now },
			LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
			},
		}
	}

	t.Run("no scope at all", func(t *testing.T) {
		dec, err := denyOf(t, newGW(), "example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonNoScope {
			t.Fatalf("reason = %s, want NO_SCOPE (err: %v)", dec.Reason, err)
		}
	})

	t.Run("revoked scope", func(t *testing.T) {
		revoked := now.Add(-1 * time.Hour)
		dec, _ := denyOf(t, newGW(scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{80},
			func(sc *storage.Scope) { sc.RevokedAt = &revoked })), "example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonScopeRevoked {
			t.Fatalf("reason = %s, want SCOPE_REVOKED", dec.Reason)
		}
	})

	t.Run("expired scope", func(t *testing.T) {
		exp := now.Add(-1 * time.Minute)
		dec, _ := denyOf(t, newGW(scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{80},
			func(sc *storage.Scope) { sc.ExpiresAt = &exp })), "example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonScopeExpired {
			t.Fatalf("reason = %s, want SCOPE_EXPIRED", dec.Reason)
		}
	})

	t.Run("deny-mode scope", func(t *testing.T) {
		dec, _ := denyOf(t, newGW(scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{80},
			func(sc *storage.Scope) { sc.Mode = "deny" })), "example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonScopeModeDeny {
			t.Fatalf("reason = %s, want SCOPE_MODE_DENY", dec.Reason)
		}
	})

	t.Run("protocol not permitted", func(t *testing.T) {
		dec, _ := denyOf(t, newGW(scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"tls"}, []int{80}, nil)),
			"example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonProtocolNotPermitted {
			t.Fatalf("reason = %s, want PROTOCOL_NOT_PERMITTED", dec.Reason)
		}
	})

	t.Run("port not permitted", func(t *testing.T) {
		dec, _ := denyOf(t, newGW(scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{8080}, nil)),
			"example.com", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonPortNotPermitted {
			t.Fatalf("reason = %s, want PORT_NOT_PERMITTED", dec.Reason)
		}
	})

	t.Run("unscoped private address", func(t *testing.T) {
		// The hostname resolves INSIDE a private range: denied even though
		// a public-variant scope exists; a private target needs an
		// EXPLICIT private range scope.
		g := newGW(scopeAt(storage.ScopeKindDomain, "internal.example", []string{"http"}, []int{80}, nil))
		g.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.168.1.5")}, nil
		}
		dec, _ := denyOf(t, g, "internal.example", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonPrivateUnscoped {
			t.Fatalf("reason = %s, want PRIVATE_UNSCOPED", dec.Reason)
		}
	})

	t.Run("loopback without explicit scope", func(t *testing.T) {
		dec, _ := denyOf(t, newGW(), "127.0.0.1", 8080, storage.ProtocolHTTP)
		if dec.Reason != ReasonPrivateUnscoped {
			t.Fatalf("reason = %s, want PRIVATE_UNSCOPED", dec.Reason)
		}
	})

	t.Run("DNS no answer", func(t *testing.T) {
		g := newGW(scopeAt(storage.ScopeKindDomain, "gone.example", []string{"http"}, []int{80}, nil))
		g.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return nil, nil // resolved to nothing — fail-closed
		}
		dec, _ := denyOf(t, g, "gone.example", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonDNSNoAnswer {
			t.Fatalf("reason = %s, want DNS_NO_ANSWER", dec.Reason)
		}
	})

	t.Run("registry unavailable fails closed", func(t *testing.T) {
		g := newGW()
		g.Store.(*fakeStore).failList = errors.New("db down")
		dec, err := g.Authorize(ctx, "example.com", 80, storage.ProtocolHTTP)
		if err == nil || !strings.Contains(err.Error(), "fail-closed") {
			t.Fatalf("registry failure must fail closed, got err=%v dec=%+v", err, dec)
		}
		if dec.Allowed {
			t.Fatalf("registry failure must never allow: %+v", dec)
		}
	})

	t.Run("invalid target", func(t *testing.T) {
		dec, _ := denyOf(t, newGW(), "not a domain!!", 80, storage.ProtocolHTTP)
		if dec.Reason != ReasonInvalidTarget {
			t.Fatalf("reason = %s, want INVALID_TARGET", dec.Reason)
		}
	})
}

func TestGatewayAllowPaths(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	scoped := scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http", "tls"}, []int{80, 8080},
		func(sc *storage.Scope) { sc.ID = 7; sc.MaxTotalBytes = 4096 })

	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scoped}},
		Now:   func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
	}

	dec, err := g.Authorize(context.Background(), "example.com", 8080, storage.ProtocolHTTP)
	if err != nil {
		t.Fatalf("want allow, got %v", err)
	}
	if !dec.Allowed || dec.Reason != "" {
		t.Fatalf("decision not allowed: %+v", dec)
	}
	if dec.Scope == nil || dec.Scope.ID != 7 {
		t.Fatalf("acting scope missing/wrong: %+v", dec.Scope)
	}
	if dec.IP.String() != "203.0.113.10" {
		t.Fatalf("decision must pin the validated address, got %s", dec.IP)
	}
	if dec.Limits.MaxTotalBytes != 4096 || dec.Limits.MaxRequests != 3 {
		t.Fatalf("limits not carried: %+v", dec.Limits)
	}
	// The allow is audited too.
	last := g.Store.(*fakeStore).audits[len(g.Store.(*fakeStore).audits)-1]
	if last.Decision != "allow" || last.ScopeID == nil || *last.ScopeID != 7 {
		t.Fatalf("allow not audited correctly: %+v", last)
	}

	// IP-literal target with the exact-ip scope.
	gExact := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http"}, []int{9000},
			func(sc *storage.Scope) { sc.ID = 3 })}},
		Now: func() time.Time { return now },
	}
	dec2, aerr := gExact.Authorize(context.Background(), "127.0.0.1", 9000, storage.ProtocolHTTP)
	if aerr != nil || !dec2.Allowed {
		t.Fatalf("explicit loopback scope must allow: dec=%+v err=%v", dec2, aerr)
	}

	// domain_suffix covers subdomains.
	gSuffix := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scopeAt(storage.ScopeKindDomainSuffix, "example.com", []string{"http"}, []int{80},
			func(sc *storage.Scope) { sc.ID = 5 })}},
		Now: func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		},
	}
	if _, aerr = gSuffix.Authorize(context.Background(), "api.example.com", 80, storage.ProtocolHTTP); aerr != nil {
		t.Fatalf("suffix scope must cover a subdomain: %v", aerr)
	}
	if _, aerr = gSuffix.Authorize(context.Background(), "notexample.com", 80, storage.ProtocolHTTP); aerr == nil {
		t.Fatalf("suffix scope must NOT cover look-alike domains")
	}
}

func TestGatewayRebindingAddressPin(t *testing.T) {
	// The hostname resolves to TWO addresses; only the first is inside
	// the scope.  The decision must pin the VALIDATED address — the
	// observers dial exactly that and never re-resolve.
	now := time.Now().UTC()
	g := &Gateway{
		Store: &fakeStore{scopes: []storage.Scope{scopeAt(storage.ScopeKindCIDR, "203.0.113.0/24", []string{"http"}, []int{80}, nil)}},
		Now:   func() time.Time { return now },
		LookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("198.51.100.66")}, nil
		},
	}
	dec, err := g.Authorize(context.Background(), "example.com", 80, storage.ProtocolHTTP)
	if err != nil || !dec.Allowed {
		t.Fatalf("want allow on the covered address: %v %+v", err, dec)
	}
	if dec.IP.String() != "203.0.113.10" {
		t.Fatalf("decision must pin the validated address: %s", dec.IP)
	}

	// Reverse case: the FIRST address is NOT covered → deny (fail-closed
	// on the pinned candidate; the second address is never validated).
	g.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("198.51.100.66"), netip.MustParseAddr("203.0.113.10")}, nil
	}
	dec2, aerr := g.Authorize(context.Background(), "example.com", 80, storage.ProtocolHTTP)
	if aerr == nil || dec2.Allowed {
		t.Fatalf("uncoved first address must deny: %+v %v", dec2, aerr)
	}
}

func TestScopeMatchingHelpers(t *testing.T) {
	sc := scopeAt(storage.ScopeKindDomainSuffix, "example.com", []string{"http"}, []int{80}, nil)
	if !sc.CoversHost("EXAMPLE.com.") {
		t.Fatalf("covers host must be case/trailing-dot insensitive")
	}
	if !sc.CoversHost("a.b.example.com") {
		t.Fatalf("suffix must cover deeper subdomains")
	}
	if sc.CoversHost("badexample.com") {
		t.Fatalf("suffix must not cover suffix-prefix look-alikes")
	}
	cidr := scopeAt(storage.ScopeKindCIDR, "203.0.113.0/25", []string{"http"}, []int{80}, nil)
	if !cidr.CoversIP(netip.MustParseAddr("203.0.113.7")) {
		t.Fatalf("cidr must contain lower half")
	}
	if cidr.CoversIP(netip.MustParseAddr("203.0.113.200")) {
		t.Fatalf("cidr must not contain upper half")
	}
	if _, err := storage.ParseScopePorts([]int{0, 70000}); err == nil {
		t.Fatalf("ports outside 1–65535 must be rejected")
	}
	if _, err := storage.ParseScopeProtocols([]string{"gopher"}); err == nil {
		t.Fatalf("unknown protocols must be rejected")
	}
}
