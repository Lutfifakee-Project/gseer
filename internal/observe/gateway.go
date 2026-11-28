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

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// gateway.go — the DEFAULT-DENY authorization boundary every active
// observer must pass.  One public entry point (Gateway.Authorize);
// every deny path is audited; no deny path ever touches the network
// beyond the DNS resolution needed to VALIDATE the destination (a deny
// never probes the target itself).
//
// Deny matrix (each is a reason code, auditable, testable):
//
//	NO_SCOPE            no active allow-scope matches the target
//	SCOPE_REVOKED       a matching scope exists but is revoked
//	SCOPE_EXPIRED       a matching scope exists but is expired
//	SCOPE_MODE_DENY     the matching registry row is a deny-mode row
//	PROTOCOL_NOT_PERMITTED the scope does not list this protocol
//	PORT_NOT_PERMITTED  the scope does not list this port
//	PRIVATE_UNSCOPED    restricted address without an explicit scope
//	DNS_NO_ANSWER       the hostname resolved to nothing (fail-closed)
//	INVALID_TARGET      the target failed normalization
//	AUDIT_UNAVAILABLE   the allow decision could not be persisted —
//	                    authorization FAILS CLOSED (v0.3.2 microfix
//	                    FIX A: an un-auditable allow is no allow)
//
// Race-condition handling (master prompt §8): authorization is
// re-checked at EVERY connection — observers pass each redirect hop
// and each new connection back through Authorize, the first hop is
// re-authorized before its request is built, and every dial passes
// Gateway.Revalidate (the pinned address, against the CURRENT registry)
// immediately before the socket connect.  A scope revoked mid-run
// therefore stops the NEXT connection at the latest, and the window
// between the final re-validation and the socket connect is the
// irreducible remainder — documented in docs/SCANNING.md, never
// overstated.

// Store is the observe-side storage contract (satisfied by BOTH the
// postgres and sqlite engines; compile-time assertions live in the cli
// package).  Deliberately minimal: the gateway reads scopes, the
// observers ingest facts and ensure their source row, and every
// decision is appended to the audit log.
type Store interface {
	// ListScopes returns the whole registry (history included;
	// Scope.Active separates live rows at decision time).
	ListScopes(ctx context.Context) ([]storage.Scope, error)
	// InsertScanAudit appends one decision (allow AND deny).
	InsertScanAudit(ctx context.Context, rec *storage.ScanAudit) error
	// EnsureSource idempotently registers the observer's source row
	// (observations.source_id FK).
	EnsureSource(ctx context.Context, name, connector, termsRef string, cfg map[string]any) (int64, error)
	// IngestFacts applies a batch through the suppression-gated,
	// idempotent pipeline (the same path every other writer uses).
	IngestFacts(ctx context.Context, facts []storage.Fact) (storage.IngestStats, error)
	// AcquireScanLease holds one of the scope's max_concurrency slots
	// for the run (cross-process; scan_leases, migration 0019/0003 +
	// token ownership 0020/0004).  storage.ErrScopeBusy = all slots
	// held by live observations.
	AcquireScanLease(ctx context.Context, scopeID int64, maxConcurrency int, ttl time.Duration, holder string) (*storage.ScanLease, error)
	// RenewScanLease extends the caller's own LIVE lease (token-scoped;
	// never revives a stolen/lapsed one).  storage.ErrLeaseLost = the
	// lease is gone — the observation must not open new connections.
	RenewScanLease(ctx context.Context, lease *storage.ScanLease, ttl time.Duration) error
	// ReleaseScanLease releases the caller's own lease (token-scoped,
	// best effort: the TTL bounds a leaked row).
	ReleaseScanLease(ctx context.Context, lease *storage.ScanLease) error
}

// Gateway decides — and audits — whether one (host, port, protocol)
// observation is authorized right now.
type Gateway struct {
	Store Store
	// Now is injectable for tests; zero value = time.Now.
	Now func() time.Time
	// LookupIP resolves one hostname (injectable for rebinding tests;
	// nil = the system resolver with a 5s timeout).
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// LeaseRenewInterval overrides the renewal heartbeat cadence for
	// tests (0 = lease TTL / DefaultLeaseRenewSplit).
	LeaseRenewInterval time.Duration
	// LeaseTTL overrides the acquisition TTL for tests (0 = the
	// engine's default, storage.DefaultScanLeaseTTL).
	LeaseTTL time.Duration
}

// Decision is one authorization answer.  IP is the validated
// destination: observers MUST dial this address (rebinding protection),
// never re-resolve Host.
type Decision struct {
	Allowed  bool
	Reason   string // "" when allowed; otherwise the deny code above
	Host     string // normalized host (lowercase, no trailing dot)
	IP       netip.Addr
	Port     int
	Protocol storage.ScopeProtocol
	Scope    *storage.Scope // the acting (or best-matching) scope; nil when none
	Limits   Limits
}

// Limits are the acting scope's execution budget.
type Limits struct {
	MaxConcurrency int
	MaxRequests    int
	MaxTotalBytes  int64 // 0 = engine default
}

// denyReason codes (audited verbatim in scan_audits.reason).
const (
	ReasonNoScope                = "NO_SCOPE"
	ReasonScopeRevoked           = "SCOPE_REVOKED"
	ReasonScopeExpired           = "SCOPE_EXPIRED"
	ReasonScopeModeDeny          = "SCOPE_MODE_DENY"
	ReasonProtocolNotPermitted   = "PROTOCOL_NOT_PERMITTED"
	ReasonPortNotPermitted       = "PORT_NOT_PERMITTED"
	ReasonPrivateUnscoped        = "PRIVATE_UNSCOPED"
	ReasonDNSNoAnswer            = "DNS_NO_ANSWER"
	ReasonInvalidTarget          = "INVALID_TARGET"
	ReasonAuthzFailureNoProbe    = "AUTHZ_FAILURE_NO_PROBE"
	ReasonScopeExistsButInactive = "SCOPE_INACTIVE"
	ReasonAuditUnavailable       = "AUDIT_UNAVAILABLE"
)

// ErrDenied is returned by MustAuthorize-style helpers; the observers
// receive the Decision and render the honest error themselves.
var ErrDenied = errors.New("observe: authorization denied")

func (d Decision) Error() string {
	if d.Allowed {
		return ""
	}
	return fmt.Sprintf("observe: %s denied by gateway: %s", d.Host, d.Reason)
}

// Authorize validates one (host, port, protocol) observation request
// against the scope registry and returns the audited Decision.
//
// host may be an IP literal (v4/v6) or a hostname.  The order is
// fail-closed: normalize → resolve (hostnames only) → private-net
// gate → scope match → audit → decide.  FIX A (v0.3.2 microfix): the
// decision is returned to the observer only after its audit row was
// durably persisted — an audit persistence failure on an ALLOW flips
// the answer to an explicit AUDIT_UNAVAILABLE deny (no probe may run
// unaudited); on a DENY the original denial stands and the audit
// failure is surfaced in the error.
func (g *Gateway) Authorize(ctx context.Context, host string, port int, proto storage.ScopeProtocol) (*Decision, error) {
	now := g.now()
	dec := &Decision{Port: port, Protocol: proto}

	// 1. Normalize the host form (IP literal vs hostname).
	normHost, isIP, addr, nerr := normalizeTarget(host)
	if nerr != nil {
		dec.Reason = ReasonInvalidTarget
		aerr := g.audit(ctx, dec, now, map[string]any{"input": host})
		return dec, auditWrapped(fmt.Errorf("E_SCOPE_DENIED: invalid target %q: %v", host, nerr), aerr)
	}
	dec.Host = normHost
	if isIP {
		dec.IP = addr
	} else {
		// 2. Resolve once; the FIRST address is pinned and validated —
		// the observers dial exactly that and never re-resolve (no other
		// address is ever used unvalidated, because no other address is
		// ever dialed).  No answer = deny (fail-closed: an unresolvable
		// target has no validated destination, so there is nothing the
		// probe could be pinned to).
		addrs, lerr := g.lookup(ctx, normHost)
		if lerr != nil || len(addrs) == 0 {
			dec.Reason = ReasonDNSNoAnswer
			aerr := g.audit(ctx, dec, now, map[string]any{"lookup_error": errString(lerr)})
			return dec, auditWrapped(
				fmt.Errorf("E_SCOPE_DENIED: target %q did not resolve (fail-closed; no probe was attempted)", normHost), aerr)
		}
		dec.IP = addrs[0]
	}

	// 3. Load the registry once and evaluate.
	scopes, serr := g.Store.ListScopes(ctx)
	if serr != nil {
		dec.Reason = ReasonAuthzFailureNoProbe
		aerr := g.audit(ctx, dec, now, map[string]any{"registry_error": serr.Error()})
		return dec, auditWrapped(
			fmt.Errorf("E_SCOPE_DENIED: scope registry unavailable (fail-closed): %v", serr), aerr)
	}

	best, reason := matchScope(scopes, now, *dec, normHost)
	if best != nil {
		dec.Scope = best
		dec.Limits = Limits{
			MaxConcurrency: best.MaxConcurrency,
			MaxRequests:    best.MaxRequests,
			MaxTotalBytes:  best.MaxTotalBytes,
		}
	}
	if reason != "" {
		dec.Reason = reason
		aerr := g.audit(ctx, dec, now, map[string]any{"matched_scope": scopeID(best)})
		return dec, auditWrapped(
			fmt.Errorf("E_SCOPE_DENIED: %s is not authorized for %s on port %d: %s (no probe was attempted)",
				dec.Host, proto, port, reason), aerr)
	}

	dec.Allowed = true
	// FIX A: the allow is audited BEFORE it is returned — persistence
	// failure flips it to an explicit deny (no duplicate row is written:
	// the failed insert persisted nothing, so there is nothing to
	// deduplicate).
	if aerr := g.audit(ctx, dec, now, map[string]any{"matched_scope": scopeID(dec.Scope)}); aerr != nil {
		dec.Allowed = false
		dec.Reason = ReasonAuditUnavailable
		return dec, fmt.Errorf("E_SCOPE_DENIED: authorization audit could not be persisted — FAIL CLOSED, no probe was attempted (AUDIT_UNAVAILABLE): %v", aerr)
	}
	return dec, nil
}

// Revalidate re-runs the full default-deny evaluation for a connection
// that is about to be dialed, WITHOUT re-resolving DNS (rebinding
// protection: the hostname is never resolved behind the pin).  It
// carries the ORIGINAL normalized hostname of the acting decision
// (final-security-microfix FIX A: the earlier signature took only the
// IP, which silently re-wrote domain/domain_suffix scopes into
// address matching and denied validly-scoped hostname targets at the
// pre-dial gate), the pinned validated address, the protocol and the
// port — everything a fresh decision considers except the resolution:
//
//	original normalized hostname   → domain / domain_suffix scopes match
//	                                 exactly as at authorization time
//	                                 (suffix boundaries enforced by
//	                                 CoversHost, never by the IP text)
//	pinned destination IP          → ip/cidr scopes + the restricted-
//	                                 address policy re-checked against
//	                                 the address that will ACTUALLY be
//	                                 dialed
//	protocol + port                → re-checked against the scope
//	expiry / revocation            → Scope.Active(now) against the
//	                                 CURRENT registry
//
// against the CURRENT registry, and audits the answer.  It is the
// observer dial path's last authorization gate: called immediately
// before every socket connect (first dial, retry, reconnect), so a
// scope revoked or expired between the initial Authorize and the dial
// still denies.
//
// Fail-closed on every error: registry unavailable, audit persistence
// failure and any deny all return an error and the caller must NOT
// dial.  The residual window between Revalidate's registry read and
// the socket connect is irreducible in userspace and documented in
// docs/SCANNING.md — the guarantee is "no connection without a
// just-audited allow of the original hostname AND the pinned address",
// never "atomic".
func (g *Gateway) Revalidate(ctx context.Context, host string, ip netip.Addr, port int, proto storage.ScopeProtocol) (*Decision, error) {
	now := g.now()
	if host == "" {
		host = ip.String() // IP-literal target: the address IS the identity
	}
	dec := &Decision{
		Port:     port,
		Protocol: proto,
		Host:     host,
		IP:       ip,
	}
	scopes, serr := g.Store.ListScopes(ctx)
	if serr != nil {
		dec.Reason = ReasonAuthzFailureNoProbe
		aerr := g.audit(ctx, dec, now, map[string]any{"registry_error": serr.Error(), "revalidate": true})
		return dec, auditWrapped(
			fmt.Errorf("E_SCOPE_DENIED: scope registry unavailable (fail-closed): %v", serr), aerr)
	}
	best, reason := matchScope(scopes, now, *dec, dec.Host)
	if best != nil {
		dec.Scope = best
		dec.Limits = Limits{
			MaxConcurrency: best.MaxConcurrency,
			MaxRequests:    best.MaxRequests,
			MaxTotalBytes:  best.MaxTotalBytes,
		}
	}
	if reason != "" {
		dec.Reason = reason
		aerr := g.audit(ctx, dec, now, map[string]any{"matched_scope": scopeID(best), "revalidate": true})
		return dec, auditWrapped(
			fmt.Errorf("E_SCOPE_DENIED: %s is not authorized for %s on port %d: %s (pre-dial re-validation; no connection was made)",
				dec.Host, proto, port, reason), aerr)
	}
	dec.Allowed = true
	if aerr := g.audit(ctx, dec, now, map[string]any{"matched_scope": scopeID(dec.Scope), "revalidate": true}); aerr != nil {
		dec.Allowed = false
		dec.Reason = ReasonAuditUnavailable
		return dec, fmt.Errorf("E_SCOPE_DENIED: pre-dial authorization audit could not be persisted — FAIL CLOSED, no connection was made (AUDIT_UNAVAILABLE): %v", aerr)
	}
	return dec, nil
}

// AcquireLease holds one of the acting scope's max_concurrency slots
// for the duration of one observation run (cross-process, DB-lease
// based; migration 0019/0003 + 0020/0004).  Busy and storage failures
// both fail closed: the caller must not probe.
func (g *Gateway) AcquireLease(ctx context.Context, dec *Decision) (*storage.ScanLease, error) {
	lease, err := g.Store.AcquireScanLease(ctx, dec.Scope.ID, dec.Limits.MaxConcurrency, g.LeaseTTL, leaseHolder())
	if err != nil {
		return nil, err // E_SCOPE_BUSY or storage failure — fail closed
	}
	return lease, nil
}

// ReleaseLease releases the run's lease (best effort: the TTL bounds a
// leaked row; a release failure never changes an observation's result).
// Release is TOKEN-scoped (migration 0020/0004): it only ever removes
// the caller's own acquisition, never a newer holder's lease.
func (g *Gateway) ReleaseLease(ctx context.Context, lease *storage.ScanLease) {
	if lease == nil {
		return
	}
	_ = g.Store.ReleaseScanLease(ctx, lease)
}

// DefaultLeaseRenewSplit — the renewal heartbeat fires every
// TTL/DefaultLeaseRenewSplit, i.e. well before expiry with a wide
// safety margin (TTL 2 min → renewal every ~40 s, ~80 s of slack).
const DefaultLeaseRenewSplit = 3

// LeaseGuard owns the renewal heartbeat of ONE observation run's lease
// (final-security-microfix FIX B part 2).  While the run is live the
// guard periodically extends the lease's expiry — token-scoped, so it
// can never revive a lease that lapsed or was stolen.  On the first
// renewal failure (storage error OR ErrLeaseLost) the guard latches
// Lost() permanently: the observation must not open any NEW
// connection (every dial path checks this gate); in-flight work
// completes honestly and the run ends.  Stop() (idempotent) ends the
// goroutine and waits for it — no renewal goroutine outlives the run.
//
// Clock-skew note: renewal compares expires_at against the ENGINE's
// own clock (single shared clock per database host), so cross-process
// skew is not a factor; the TTL/3 cadence leaves ~2/3 TTL of slack for
// scheduling hiccups before any expiry boundary matters.
type LeaseGuard struct {
	gw       *Gateway
	lease    *storage.ScanLease
	ttl      time.Duration
	interval time.Duration
	lost     atomic.Bool
	stopOnce sync.Once
	stopped  chan struct{}
	done     chan struct{}
}

// StartLeaseRenewal launches the renewal heartbeat for the run's
// lease.  interval <= 0 derives from the lease TTL (TTL/3); tests may
// inject a shorter cadence.  The caller MUST Stop() the guard when the
// run ends (defer).
func (g *Gateway) StartLeaseRenewal(ctx context.Context, lease *storage.ScanLease) *LeaseGuard {
	ttl := lease.ExpiresAt.Sub(lease.AcquiredAt)
	if ttl <= 0 {
		ttl = storage.DefaultScanLeaseTTL
	}
	interval := g.LeaseRenewInterval
	if interval <= 0 {
		interval = ttl / DefaultLeaseRenewSplit
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	lg := &LeaseGuard{
		gw:       g,
		lease:    lease,
		ttl:      ttl,
		interval: interval,
		stopped:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	go lg.loop(ctx)
	return lg
}

// loop renews on the cadence until stopped, the run context is
// canceled, or a renewal fails (then Lost() latches and the heartbeat
// ends — the lease is gone or the storage is down; either way the
// observation may not open new connections).
func (lg *LeaseGuard) loop(ctx context.Context) {
	defer close(lg.done)
	ticker := time.NewTicker(lg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-lg.stopped:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewed := *lg.lease
			if err := lg.gw.Store.RenewScanLease(ctx, &renewed, lg.ttl); err != nil {
				lg.lost.Store(true)
				return
			}
			lg.lease.ExpiresAt = renewed.ExpiresAt
		}
	}
}

// Lost reports whether the run's lease is gone (renewal failed):
// dial paths MUST refuse to open any new connection while true.
func (lg *LeaseGuard) Lost() bool {
	return lg != nil && lg.lost.Load()
}

// Stop ends the heartbeat and waits for its goroutine (idempotent;
// double Stop is safe).  After Stop the lease still holds until the
// run's ReleaseLease — the last renewal window is covered by the
// remaining expiry margin.
func (lg *LeaseGuard) Stop() {
	if lg == nil {
		return
	}
	lg.stopOnce.Do(func() { close(lg.stopped) })
	<-lg.done
}

// leaseHolder identifies the observing process in scan_leases rows
// (hostname#pid — audit-quality DIAGNOSTIC provenance, best effort).
// Ownership is the per-acquisition token, never this string.
func leaseHolder() string {
	h, err := os.Hostname()
	if err != nil {
		h = "unknown-host"
	}
	return fmt.Sprintf("%s#%d", h, os.Getpid())
}

// matchScope finds the acting scope for the decision, or the deny
// reason.  Precedence (first match wins, deny-codes dominate):
//  1. an ACTIVE allow-scope covering host or IP, protocol AND port ok → allowed;
//  2. an ACTIVE allow-scope covering the target but protocol/port not
//     listed → PROTOCOL_NOT_PERMITTED / PORT_NOT_PERMITTED;
//  3. an INACTIVE matching scope (revoked/expired/deny-mode) → its reason;
//  4. a restricted address with no covering scope → PRIVATE_UNSCOPED;
//  5. nothing → NO_SCOPE.
func matchScope(scopes []storage.Scope, now time.Time, dec Decision, normHost string) (*storage.Scope, string) {
	var (
		activeMismatch   *storage.Scope
		reason           string // reason for the best inactive match
		restricted       bool
		restrictedNoAddr bool // restricted target, no active scope covers the ADDRESS
	)
	restricted = isRestrictedIP(dec.IP)

	for i := range scopes {
		sc := &scopes[i]
		if !sc.CoversHost(normHost) && !sc.CoversIP(dec.IP) {
			continue
		}
		if !sc.Active(now) {
			// record the most specific inactive reason (revoked beats
			// expired beats deny-mode for audit clarity)
			r := inactiveReason(*sc, now)
			if reason == "" {
				reason = r
			}
			continue
		}
		if !sc.AllowsProtocol(dec.Protocol) {
			if activeMismatch == nil {
				activeMismatch = sc
			}
			continue
		}
		if !sc.AllowsPort(dec.Port) {
			if activeMismatch == nil {
				activeMismatch = sc
			}
			continue
		}
		// An active, protocol- and port-permitting scope.  For restricted
		// addresses the scope must cover the ADDRESS (not just the
		// hostname) — an operator names the private range explicitly.
		if restricted && !sc.CoversIP(dec.IP) {
			restrictedNoAddr = true
			continue
		}
		return sc, ""
	}

	if activeMismatch != nil {
		if !activeMismatch.AllowsProtocol(dec.Protocol) {
			return nil, ReasonProtocolNotPermitted
		}
		return nil, ReasonPortNotPermitted
	}
	if reason != "" {
		return nil, reason
	}
	if restricted {
		// The hard safety boundary: no active scope covers the address
		// itself (or no scope at all).  This reason dominates the softer
		// protocol/port mismatches.
		if restrictedNoAddr || activeMismatch == nil {
			return nil, ReasonPrivateUnscoped
		}
	}
	if activeMismatch != nil {
		if !activeMismatch.AllowsProtocol(dec.Protocol) {
			return nil, ReasonProtocolNotPermitted
		}
		return nil, ReasonPortNotPermitted
	}
	return nil, ReasonNoScope
}

func inactiveReason(sc storage.Scope, now time.Time) string {
	if sc.Mode != "allow" {
		return ReasonScopeModeDeny
	}
	if sc.RevokedAt != nil && !sc.RevokedAt.After(now) {
		return ReasonScopeRevoked
	}
	if sc.ExpiresAt != nil && !sc.ExpiresAt.After(now) {
		return ReasonScopeExpired
	}
	return ReasonScopeExistsButInactive
}

// isRestrictedIP reports whether addr needs an EXPLICIT address-level
// scope: loopback, RFC 1918 / ULA private space, link-local, CGNAT
// (100.64/10), multicast and the unspecified address.
func isRestrictedIP(addr netip.Addr) bool {
	a := addr.Unmap()
	if !a.IsValid() {
		return true
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10 (netip has no direct predicate).
	if a.Is4() {
		o := a.As4()
		return o[0] == 100 && o[1] >= 64 && o[1] <= 127
	}
	return false
}

// normalizeTarget canonicalizes the operator's target string: IP
// literals pass NormalizeIP; hostnames pass NormalizeDomain (lowercase,
// IDNA, trailing-dot strip).  The bool reports an IP literal; the Addr
// is valid only then.
func normalizeTarget(host string) (string, bool, netip.Addr, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", false, netip.Addr{}, errors.New("empty target host")
	}
	if _, iperr := suppress.NormalizeIP(h); iperr == nil {
		return h, true, netip.MustParseAddr(h), nil
	}
	d, derr := suppress.NormalizeDomain(h)
	if derr != nil {
		return "", false, netip.Addr{}, derr
	}
	return d, false, netip.Addr{}, nil
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

func (g *Gateway) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.LookupIP != nil {
		return g.LookupIP(ctx, host)
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lctx, host)
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if na, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, na.Unmap())
		}
	}
	return out, err
}

// audit appends one decision row and returns the persistence error,
// if any.  FIX A (v0.3.2 microfix): the error is PROPAGATED, never
// swallowed — Authorize fails an allow whose audit could not be
// persisted and surfaces the failure on every deny.  A failed insert
// wrote no row, so propagating the error cannot duplicate audit rows;
// detail keeps the in-memory audit_error note for fakes that record
// the attempt.
func (g *Gateway) audit(ctx context.Context, dec *Decision, now time.Time, detail map[string]any) error {
	port := dec.Port
	var scopeID *int64
	if dec.Scope != nil {
		scopeID = &dec.Scope.ID
	}
	rec := &storage.ScanAudit{
		TS:         now,
		TargetHost: dec.Host,
		TargetIP:   ipText(dec.IP),
		Port:       &port,
		Protocol:   string(dec.Protocol),
		Decision:   decisionText(dec.Allowed),
		Reason:     dec.Reason,
		ScopeID:    scopeID,
		Detail:     detail,
	}
	if err := g.Store.InsertScanAudit(ctx, rec); err != nil {
		detail["audit_error"] = err.Error()
		return err
	}
	return nil
}

// auditWrapped attaches an audit-persistence failure to a decision
// error without changing its classification (the deny reason and the
// E_SCOPE_DENIED exit-code vocabulary stay intact).
func auditWrapped(decErr, auditErr error) error {
	if auditErr == nil {
		return decErr
	}
	return fmt.Errorf("%v (AUDIT persistence also failed: %v)", decErr, auditErr)
}

func ipText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func decisionText(ok bool) string {
	if ok {
		return "allow"
	}
	return "deny"
}

func scopeID(sc *storage.Scope) any {
	if sc == nil {
		return nil
	}
	return sc.ID
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
