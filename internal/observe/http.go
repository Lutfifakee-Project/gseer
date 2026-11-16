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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// http.go — the ACTIVE HTTP observer (v0.3.2): one explicit,
// gateway-authorized HTTP GET against a scoped target, recorded as a
// service-level fact with HTTP evidence whose keys feed the existing
// latest_http view (status / title / server land directly in the
// search_index http_* columns).
//
// Behavior contract:
//   - the initial request AND every redirect hop re-enter the gateway
//     (Authorize) — including the FIRST hop (v0.3.2 microfix FIX B: the
//     initial decision is never trusted across the gap to the first
//     connection); a denied hop ends the chain — the chain-so-far is
//     still recorded honestly;
//   - every dial — first, retry, reconnect — passes Gateway.Revalidate
//     (the pinned address against the CURRENT registry) immediately
//     before the socket connect; a revoked scope denies with NO
//     connection;
//   - the client dials the gateway's VALIDATED address only (the URL
//     carries the IP literal; the Host header carries the operator's
//     hostname for virtual hosting) — the hostname is never re-resolved
//     behind the gateway's back (rebinding protection);
//   - redirects to https:// are RECORDED as the final hop, not followed:
//     TLS is the separate TLS observer's scope ('gseer scan tls');
//   - only plain http:// is spoken here; the scope must list 'http';
//   - the response bodies are capped by the scope's ACCUMULATED budget
//     (MaxTotalBytes, else DefaultMaxBytes): the counter spans EVERY
//     redirect hop of the run and is never reset on a redirect (v0.3.2
//     microfix FIX C); truncation is recorded, never silently parsed;
//   - a connection failure is an OBSERVATION OF FAILURE (asset-level,
//     evidence scan.result='failed') — it is never recorded as absence;
//   - the run holds one of the scope's max_concurrency lease slots
//     (cross-process, scan_leases) and fails closed when none is free.

// SourceHTTP is the observations.source row the HTTP observer runs
// under (idempotently ensured per run).
const SourceHTTP = "scan-http"

// ProvenanceHTTP is the observations.provenance label for HTTP scans.
const ProvenanceHTTP = "scan-http"

// HTTPObserver defaults (polite, bounded, honest).
const (
	DefaultHTTPMaxBytes  = 64 << 10 // 64 KiB — title/server metadata needs little
	DefaultHTTPTimeout   = 10 * time.Second
	DefaultMaxRedirects  = 5
	HTTPTermsRef         = "operator-scoped active observation (default-deny gateway; docs/SCANNING.md)"
	DefaultScanUserAgent = "GSEER/0.3.2 (authorized observation of operator-scoped target)"
)

// HTTPObserver runs gateway-authorized HTTP observations.
type HTTPObserver struct {
	GW *Gateway

	// DefaultMaxBytes applies when the acting scope leaves
	// MaxTotalBytes unset (0).  MaxBytesOverride (tests) wins over both.
	DefaultMaxBytes  int64
	MaxBytesOverride int64
	// Timeout bounds dial + response headers (per hop).
	Timeout time.Duration
	// UserAgent identifies the observer honestly.
	UserAgent string
}

// ScanResult is one observation run, as the CLI prints it.
type ScanResult struct {
	Protocol   string   `json:"protocol"`
	Host       string   `json:"host"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	OK         bool     `json:"ok"`
	Failure    string   `json:"failure,omitempty"`
	Status     int      `json:"status,omitempty"`
	Title      string   `json:"title,omitempty"`
	Server     string   `json:"server,omitempty"`
	Redirects  []string `json:"redirects,omitempty"`
	Facts      int      `json:"facts"`
	Ingested   int      `json:"ingested"`
	Deduped    int      `json:"deduped"`
	ScopeID    int64    `json:"scope_id,omitempty"`
	Provenance string   `json:"provenance"`
	Truncated  bool     `json:"truncated,omitempty"`
	// BytesRead is the ACCUMULATED response-body byte count of the run
	// (every redirect hop included; the metric is bytes actually read
	// from the bodies, headers excluded).
	BytesRead int64 `json:"bytes_read"`
}

// runBudgets resolves the run's byte budget, timeout, and user agent:
// the scope's limits win, then the observer's configured defaults, then
// the package defaults (FIX C: the budget returned is the ACCUMULATED
// run budget — the caller counts every hop against it).
func (o *HTTPObserver) runBudgets(dec *Decision) (maxBytes int64, timeout time.Duration, ua string) {
	maxBytes = dec.Limits.MaxTotalBytes
	if maxBytes <= 0 {
		maxBytes = o.DefaultMaxBytes
	}
	if o.MaxBytesOverride > 0 {
		maxBytes = o.MaxBytesOverride
	}
	if maxBytes <= 0 {
		maxBytes = DefaultHTTPMaxBytes
	}
	timeout = o.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	ua = o.UserAgent
	if ua == "" {
		ua = DefaultScanUserAgent
	}
	return maxBytes, timeout, ua
}

// Run performs one HTTP observation.  The error return carries only
// authorization/storage failures that prevented the run entirely;
// observation-level failures (dial refused, timeout, bad status) are
// RECORDED as failed-observation facts and reported in Result.OK/Failure.
func (o *HTTPObserver) Run(ctx context.Context, host string, port int) (*ScanResult, error) {
	res := &ScanResult{Protocol: string(storage.ProtocolHTTP), Port: port, Provenance: ProvenanceHTTP}

	// 1. Gateway (first check; the dialer re-checks below — race handling).
	dec, aerr := o.GW.Authorize(ctx, host, port, storage.ProtocolHTTP)
	if aerr != nil {
		return res, aerr // audited inside the gateway; NO probe fires
	}
	res.Host = dec.Host
	res.IP = ipText(dec.IP)
	res.ScopeID = dec.Scope.ID

	// 2. Source row (idempotent).
	sourceID, serr := o.GW.Store.EnsureSource(ctx, SourceHTTP, "scan-http", HTTPTermsRef, map[string]any{
		"scope_id": dec.Scope.ID,
		"target":   fmt.Sprintf("%s:%d", dec.Host, port),
	})
	if serr != nil {
		return res, fmt.Errorf("cannot ensure the %s source row: %v", SourceHTTP, serr)
	}

	// 2b. Concurrency lease (v0.3.2 microfix FIX D + final-security-
	// microfix FIX B): hold one of the scope's max_concurrency slots
	// for the whole run — cross-process via the scan_leases table, with
	// a per-acquisition TOKEN and a renewal heartbeat (TTL/3).  Busy
	// (E_SCOPE_BUSY) and any storage failure FAIL CLOSED: no probe is
	// sent.  Released (token-scoped) at run end; the TTL bounds a
	// leaked row if the process dies.
	lease, lerr := o.GW.AcquireLease(ctx, dec)
	if lerr != nil {
		return res, lerr
	}
	defer o.GW.ReleaseLease(ctx, lease)
	leaseGuard := o.GW.StartLeaseRenewal(ctx, lease)
	defer leaseGuard.Stop()

	// maxBytes is the run's ACCUMULATED response-body budget (FIX C):
	// counted across every redirect hop, never reset on a redirect.
	maxBytes, timeout, ua := o.runBudgets(dec)
	remaining := maxBytes
	bytesRead := int64(0)

	now := o.GW.now()

	// 3. The observation loop: one authorized hop per request.
	var (
		status  int
		title   string
		server  string
		cType   string
		hops    []string
		trunc   bool
		finalIP = dec.IP
	)
	curHost, curPort, curPath := dec.Host, port, "/"
	// curIP is ALWAYS the freshly authorized hop's validated address
	// (set from hd.IP before any use — the initializer would be dead).
	var curIP netip.Addr
	budget := max(dec.Limits.MaxRequests, 1)
	failure := ""

	// finish is the observation loop's single exit path: it assembles
	// the honest evidence + facts (whatever the loop recorded — a
	// complete response, a failure, a denied hop, an exhausted budget)
	// and returns the run result.
	finish := func() (*ScanResult, error) {
		evidence := buildHTTPScanEvidence(status, title, server, cType, failure,
			dec.Scope.ID, net.JoinHostPort(dec.Host, strconv.Itoa(port)), finalIP, hops,
			bytesRead, maxBytes, trunc)
		facts := scanFacts(now, sourceID, SourceHTTP, ProvenanceHTTP, dec.Host, finalIP, port,
			serviceProtocolHTTP, evidence, dec.Scope.ID)
		stats, ierr := o.GW.Store.IngestFacts(ctx, facts)
		if ierr != nil {
			return res, fmt.Errorf("cannot ingest the observation facts: %v", ierr)
		}
		res.OK = failure == ""
		res.Failure = failure
		res.Status = status
		res.Title = title
		res.Server = server
		res.Redirects = hops
		res.Truncated = trunc
		res.BytesRead = bytesRead
		res.Facts = len(facts)
		res.Ingested = stats.AssetsInserted + stats.ServicesInserted + stats.ObservationsInserted
		res.Deduped = stats.ObservationsDeduped
		return res, nil
	}

	for hop := 0; ; hop++ {
		// FIX B: a lost concurrency lease (renewal failure) is fatal for
		// the observation — no NEW connection may be opened.
		if leaseGuard.Lost() {
			failure = "concurrency lease lost (renewal failure) — no new connection"
			return finish()
		}
		// FIX B: EVERY hop — including the first — re-enters the gateway
		// immediately before its request.  The first hop re-checks the
		// initial decision (revocation/expiry between Authorize and the
		// first connection denies before anything is sent); every
		// redirect hop independently revalidates the NEW destination;
		// and the dial itself revalidates once more via clientFor's
		// DialContext → Gateway.Revalidate.
		hd, herr := o.GW.Authorize(ctx, curHost, curPort, storage.ProtocolHTTP)
		if herr != nil {
			if hop == 0 {
				// Revoked, expired or out-of-scope between the initial
				// authorization and the first connection: fail exactly
				// like the initial check — nothing was sent, the denial
				// is audited, E_SCOPE_DENIED (exit 5).
				return res, herr
			}
			// A denied redirect hop ends the chain; the chain-so-far is kept.
			hops = append(hops, fmt.Sprintf("DENIED %s: %s", net.JoinHostPort(curHost, strconv.Itoa(curPort)), reasonOf(hd)))
			failure = fmt.Sprintf("redirect hop denied by gateway: %s", reasonOf(hd))
			return finish()
		}
		curIP = hd.IP
		finalIP = hd.IP
		if hop >= budget {
			failure = fmt.Sprintf("request budget exhausted (scope max_requests=%d)", budget)
			return finish()
		}
		if remaining <= 0 {
			// The accumulated budget is gone: the next hop is recorded,
			// not sent (FIX C — the counter spans the whole run).
			failure = fmt.Sprintf("response-byte budget exhausted (scope max_total_bytes=%d, %d bytes read across %d hop(s))",
				maxBytes, bytesRead, hop)
			return finish()
		}

		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, hopURL(curIP, curPort, curPath), nil)
		if rerr != nil {
			failure = "internal: cannot build request: " + rerr.Error()
			return finish()
		}
		req.Host = curHost // virtual hosting; the DIAL goes to curIP
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")

		client := o.clientFor(o.GW, leaseGuard, hd.Host, curIP, curPort, timeout)
		resp, derr := client.Do(req)
		if derr != nil {
			// A failed connection is an observation OF FAILURE — recorded
			// below; never treated as "asset absent".  This includes the
			// pre-dial re-validation denial (nothing connected).
			failure = errText(derr)
			return finish()
		}
		hops = append(hops, fmt.Sprintf("%s %d", net.JoinHostPort(curHost, strconv.Itoa(curPort)), resp.StatusCode))
		status = resp.StatusCode
		server = resp.Header.Get("Server")
		cType = resp.Header.Get("Content-Type")

		// FIX C: the per-hop read consumes the REMAINING budget; the
		// counter accumulates across hops and is never reset.  Read
		// errors are surfaced honestly (never reported as a complete
		// response).
		body, tread, used, rderr := readCapped(resp.Body, remaining)
		bytesRead += used
		remaining = max(remaining-used, 0) // clamped — cannot underflow
		_ = resp.Body.Close()
		if rderr != nil {
			failure = fmt.Sprintf("response body read error after %d of %d budget bytes: %v", bytesRead, maxBytes, rderr)
			return finish()
		}
		trunc = trunc || tread
		title = extractTitle(body)

		if isRedirect(status) {
			loc := resp.Header.Get("Location")
			next, action, perr := decideRedirect(loc, curHost, curPort, hop)
			switch action {
			case redirectStopEmptyLoc:
				res.Redirects = hops
				return finish()
			case redirectStopUnparseable:
				failure = "unparseable redirect Location: " + perr.Error()
				return finish()
			case redirectStopRecorded:
				hops = append(hops, next.target) // the pre-rendered RECORDED-NOT-FOLLOWED note
				res.Redirects = hops
				return finish()
			default: // redirectFollow
				curHost, curPort, curPath = next.host, next.port, next.path
				continue
			}
		}
		return finish()
	}
}

// serviceProtocolHTTP is the services.protocol value recorded by the
// HTTP observer (the transport-level protocol the asset serves).
const serviceProtocolHTTP = "http"

// redirectAction is the Run loop's decision for one redirect hop.
type redirectAction int

const (
	redirectFollow          redirectAction = iota // dial the resolved target
	redirectStopEmptyLoc                          // no Location header — the chain ends here
	redirectStopUnparseable                       // Location failed to parse (error carried separately)
	redirectStopRecorded                          // recorded, NOT followed (off-contract scheme or depth limit)
)

// decideRedirect resolves one redirect Location into the next hop.
// Pure: the Run loop owns all state transitions and hop recording.
func decideRedirect(loc, curHost string, curPort int, hop int) (redirectTarget, redirectAction, error) {
	if loc == "" {
		return redirectTarget{}, redirectStopEmptyLoc, nil
	}
	next, perr := resolveRedirect(loc, curHost, curPort)
	if perr != nil {
		return redirectTarget{}, redirectStopUnparseable, perr
	}
	if next.scheme != "http" {
		// Recorded, not followed — TLS is the separate observer.
		next.target = fmt.Sprintf("RECORDED-NOT-FOLLOWED %s (scheme %q — use `gseer scan tls`)", next.target, next.scheme)
		return next, redirectStopRecorded, nil
	}
	if hop+1 >= DefaultMaxRedirects {
		next.target = "RECORDED-NOT-FOLLOWED redirect depth limit"
		return next, redirectStopRecorded, nil
	}
	return next, redirectFollow, nil
}

// buildHTTPScanEvidence assembles the run's evidence object: exactly
// what the target answered (or the honest failure), with the
// ACCUMULATED byte counter the scope budget was measured against.
func buildHTTPScanEvidence(status int, title, server, cType, failure string,
	scopeID int64, target string, finalIP netip.Addr, hops []string,
	bytesRead, maxBytes int64, trunc bool,
) map[string]any {
	evidence := map[string]any{
		"http": map[string]any{
			"status":       status,
			"title":        title,
			"server":       server,
			"content_type": cType,
		},
		"scan": map[string]any{
			"scope_id":       scopeID,
			"target":         target,
			"observed_ip":    finalIP.String(),
			"hops":           hops,
			"response_bytes": bytesRead, // ACCUMULATED body bytes (FIX C)
			"byte_budget":    maxBytes,
		},
		"confidence": confidenceFor(failure),
	}
	if failure != "" {
		evidence["scan"].(map[string]any)["result"] = "failed"
		evidence["scan"].(map[string]any)["error"] = failure
	} else {
		evidence["scan"].(map[string]any)["result"] = "observed"
	}
	if trunc {
		evidence["scan"].(map[string]any)["body_truncated"] = true
	}
	return evidence
}

// clientFor builds one client per hop: it dials ONLY the validated
// address (the URL carries the IP literal; this dialer refuses any
// other destination as a belt-and-braces rebinding guard) and disables
// auto-redirects (the loop above authorizes each hop explicitly).
//
// FIX B: the dialer's DialContext is the LAST authorization gate — it
// checks the lease guard (a lost lease = no new connections, ever) and
// calls Gateway.Revalidate (ORIGINAL hostname + pinned address vs the
// CURRENT registry, audited — no DNS re-resolution) immediately before
// every socket connect.  This covers the first dial, every transport
// retry and every reconnect: a scope that was revoked or expired after
// the hop's Authorize denies here and NOTHING connects.  The residual
// window between the registry read and the connect syscall is
// irreducible in userspace and documented in docs/SCANNING.md — never
// overstated.
func (o *HTTPObserver) clientFor(gw *Gateway, guard *LeaseGuard, host string, ip netip.Addr, port int, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	pinned := ip.String()
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, p, serr := net.SplitHostPort(addr)
				if serr == nil && !strings.EqualFold(h, pinned) {
					// The URL's host IS the pinned IP; anything else here
					// would be a bypass — refuse it.
					return nil, fmt.Errorf("observe: dial target %q is not the gateway-validated address %q", addr, net.JoinHostPort(pinned, p))
				}
				if guard.Lost() {
					// FIX B: the run's concurrency lease is gone — no new
					// connection may be opened.
					return nil, fmt.Errorf("observe: concurrency lease lost (renewal failure) — FAIL CLOSED, no new connection")
				}
				if _, rerr := gw.Revalidate(ctx, host, ip, port, storage.ProtocolHTTP); rerr != nil {
					// Fail closed: no socket is opened after a failed
					// (or un-auditable) re-validation.
					return nil, rerr
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(pinned, strconv.Itoa(port)))
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // the Run loop owns redirects
		},
	}
}

func hopURL(ip netip.Addr, port int, path string) string {
	hostPart := ip.String()
	if ip.Is6() && !ip.Is4In6() {
		hostPart = "[" + ip.String() + "]"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "http://" + hostPart + ":" + strconv.Itoa(port) + path
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther ||
		status == http.StatusTemporaryRedirect ||
		status == http.StatusPermanentRedirect
}

// redirectTarget is one resolved redirect hop.
type redirectTarget struct {
	scheme string
	host   string
	port   int
	path   string
	target string
}

// resolveRedirect resolves one Location header against the current hop.
// Relative Locations keep speaking to the SAME validated address (the
// pinned IP is retained; only the Host header name carries over).
func resolveRedirect(loc, curHost string, curPort int) (redirectTarget, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return redirectTarget{}, err
	}
	out := redirectTarget{scheme: u.Scheme}
	pathOf := func(u *url.URL) string {
		p := u.EscapedPath()
		if p == "" {
			p = "/"
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		return p
	}
	if u.IsAbs() {
		if u.Scheme != "http" {
			out.target = u.String()
			return out, nil // recorded-not-followed path
		}
		out.host = u.Hostname()
		if p, perr := strconv.Atoi(u.Port()); perr == nil {
			out.port = p
		}
		out.path = pathOf(u)
		out.target = u.String()
	} else {
		// A relative Location is a SAME-ORIGIN hop: same scheme (this
		// observer speaks http only), same validated address, same port,
		// new path.
		out.scheme = "http"
		out.host = curHost
		out.port = curPort
		out.path = pathOf(u)
		out.target = loc
	}
	if out.port == 0 {
		out.port = 80
	}
	// Normalize a NEW absolute host the same way the gateway does (a
	// relative Location keeps the current host verbatim).
	if out.host != curHost {
		nh, _, _, nerr := normalizeTarget(out.host)
		if nerr != nil {
			return redirectTarget{}, nerr
		}
		out.host = nh
	}
	return out, nil
}

// readCapped reads up to `remaining` bytes of one response body.
//
// FIX C semantics (one precise metric, used consistently):
//   - used      = the bytes actually READ from the body, headers
//     excluded — including the single one-byte truncation probe when
//     the body exceeded the remaining budget (the probe is read, so it
//     is counted);
//   - truncated = the body had more than the remaining budget;
//   - rerr      = a read error (mid-body failure) — propagated honestly:
//     the caller records the run as FAILED, never as a complete
//     response.
//
// Integer safety: used is bounded by remaining+1 (clamped at MaxInt64),
// so the caller's subtraction cannot underflow and the accumulation
// cannot overflow int64 for any realistic body stream.
func readCapped(r io.Reader, remaining int64) (b []byte, truncated bool, used int64, rerr error) {
	if remaining <= 0 {
		return nil, false, 0, nil
	}
	limit := remaining
	if limit < math.MaxInt64 {
		limit++
	}
	limited := io.LimitReader(r, limit)
	b, err := io.ReadAll(limited)
	used = int64(len(b))
	if err != nil && used == 0 {
		return nil, false, 0, err
	}
	if used > remaining {
		return b[:remaining], true, used, err
	}
	return b, false, used, err
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle pulls the <title> from a capped HTML body (best effort —
// the raw body is never stored).
func extractTitle(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func reasonOf(dec *Decision) string {
	if dec == nil {
		return ReasonNoScope
	}
	return dec.Reason
}

func errText(err error) string {
	s := err.Error()
	if i := strings.Index(s, ": "); i > 0 && strings.Count(s, ": ") > 2 {
		// keep the net-layer message readable in evidence
		s = strings.ReplaceAll(s, "\n", " ")
	}
	return s
}

func confidenceFor(failure string) string {
	if failure != "" {
		return "low"
	}
	return "high"
}

// payloadHashHex is the L2 fact-identity hash primitive for observers
// (identical semantics to the collect package's hexSHA256: hash of the
// canonical JSON — encoding/json sorts map keys).
func payloadHashHex(evidence map[string]any) string {
	b, err := json.Marshal(evidence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
