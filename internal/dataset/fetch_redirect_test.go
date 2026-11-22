// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// fetch_redirect_test.go — R4 P0-5 regression battery for the dataset
// fetcher's redirect policy.  The per-hop policy (redirectPolicy) is
// exercised at unit level with synthetic URLs — fully deterministic,
// no network — plus one real-client integration test through an
// httptest same-host redirect chain.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/config"
)

// req builds an http.Request for a URL (errors are test failures).
func req(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	r, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatalf("build request %q: %v", raw, err)
	}
	return r
}

// withResolver pins the host-resolution seam for the duration of one
// test (deterministic addresses for fake CDN hostnames).
func withResolver(t *testing.T, hosts map[string][]string) {
	t.Helper()
	old := resolveHostIPsFn
	resolveHostIPsFn = func(host string) ([]net.IP, error) {
		if ips, ok := hosts[host]; ok {
			out := make([]net.IP, 0, len(ips))
			for _, s := range ips {
				ip := net.ParseIP(s)
				if ip == nil {
					return nil, &net.DNSError{Err: "bad test fixture", Name: host}
				}
				out = append(out, ip)
			}
			return out, nil
		}
		return old(host)
	}
	t.Cleanup(func() { resolveHostIPsFn = old })
}

// TestRedirectDowngradeRefused — an https origin is never redirected to
// plain http, whatever the target.
func TestRedirectDowngradeRefused(t *testing.T) {
	f := NewFetcher()
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	for _, target := range []string{
		"http://channel.example/central-dataset/gseer-dataset.ndjson.gz", // same host
		"http://93.184.216.34/payload.gz",                                // other host
	} {
		err := f.redirectPolicy(req(t, target), via)
		if err == nil || !strings.Contains(err.Error(), "E_DATASET_REDIRECT") || !strings.Contains(err.Error(), "downgrade") {
			t.Errorf("https→http downgrade must be refused (%s): %v", target, err)
		}
	}
}

// TestRedirectPlainHTTPOnlyBetweenLoopbackHosts — the local-testing
// exception: http→http between loopback hosts is allowed; anything
// non-loopback is refused.
func TestRedirectPlainHTTPOnlyBetweenLoopbackHosts(t *testing.T) {
	f := NewFetcher()
	via := []*http.Request{req(t, "http://127.0.0.1:9001/gseer-dataset-manifest.json")}
	if err := f.redirectPolicy(req(t, "http://127.0.0.1:9002/gseer-dataset.ndjson.gz"), via); err != nil {
		t.Errorf("loopback→loopback http hop must be allowed: %v", err)
	}
	err := f.redirectPolicy(req(t, "http://10.0.0.1/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_REDIRECT") {
		t.Errorf("loopback→private http hop must be refused: %v", err)
	}
}

// TestRedirectProhibitedDestinationsRefused — cross-host hops to
// loopback, RFC1918, CGNAT, link-local, multicast are refused (literal
// IPs).
func TestRedirectProhibitedDestinationsRefused(t *testing.T) {
	f := NewFetcher()
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	for _, bad := range []string{
		"https://127.0.0.1/payload.gz",
		"https://[::1]/payload.gz",
		"https://192.168.1.10/payload.gz",
		"https://10.9.8.7/payload.gz",
		"https://172.16.5.5/payload.gz",
		"https://100.64.0.9/payload.gz",   // CGNAT
		"https://169.254.169.254/payload", // link-local metadata
		"https://224.0.0.1/payload.gz",    // multicast
		"https://0.0.0.0/payload.gz",      // unspecified
		"https://198.18.0.3/payload.gz",   // benchmark
	} {
		err := f.redirectPolicy(req(t, bad), via)
		if err == nil || !strings.Contains(err.Error(), "E_DATASET_REDIRECT") {
			t.Errorf("prohibited destination %s must be refused: %v", bad, err)
		}
	}
}

// TestRedirectHostnameResolvingToPrivateRefused — the SSRF check covers
// RESOLVED addresses, not just literals: a public-looking hostname that
// resolves into a private range is refused.
func TestRedirectHostnameResolvingToPrivateRefused(t *testing.T) {
	withResolver(t, map[string][]string{"cdn-trap.example": {"93.184.216.34", "192.168.0.44"}})
	f := NewFetcher()
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	err := f.redirectPolicy(req(t, "https://cdn-trap.example/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "prohibited") {
		t.Errorf("hostname resolving to a private address must be refused: %v", err)
	}
}

// TestRedirectCrossHostUntrustedRefused — a cross-host hop to a
// non-trusted host fails closed; an unresolvable host is refused too
// (no blind dialing).
func TestRedirectCrossHostUntrustedRefused(t *testing.T) {
	withResolver(t, map[string][]string{"evil.example": {"93.184.216.34"}})
	f := NewFetcher()
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	err := f.redirectPolicy(req(t, "https://evil.example/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Errorf("cross-host hop to an untrusted host must be refused: %v", err)
	}
	err = f.redirectPolicy(req(t, "https://never-resolves.invalid/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_REDIRECT") {
		t.Errorf("an unresolvable cross-host target must be refused (fail closed): %v", err)
	}
}

// TestRedirectTrustedCDNAllowed — the legitimate-CDN path: a cross-host
// hop to an EXPLICITLY trusted host is allowed (and the same fetch to
// an untrusted host still fails).
func TestRedirectTrustedCDNAllowed(t *testing.T) {
	withResolver(t, map[string][]string{"cdn.trusted.example": {"93.184.216.34"}, "cdn.other.example": {"93.184.216.35"}})
	f := NewFetcher()
	f.TrustedRedirectHosts = []string{"cdn.trusted.example"}
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	if err := f.redirectPolicy(req(t, "https://cdn.trusted.example/payload.gz"), via); err != nil {
		t.Errorf("cross-host hop to the trusted CDN must be allowed: %v", err)
	}
	err := f.redirectPolicy(req(t, "https://cdn.other.example/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Errorf("a host NOT in the trusted list must still be refused: %v", err)
	}
}

// TestRedirectSameHostAllowed — same-host hops skip the destination
// checks (the operator chose that origin) but still obey the transport
// and limit rules.
func TestRedirectSameHostAllowed(t *testing.T) {
	f := NewFetcher()
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	if err := f.redirectPolicy(req(t, "https://channel.example/central-dataset/gseer-dataset.ndjson.gz"), via); err != nil {
		t.Errorf("same-host https hop must be allowed: %v", err)
	}
}

// TestRedirectLimitAndLoop — more hops than the limit are refused; a
// redirect loop trips the same limit (E_DATASET_REDIRECT).
func TestRedirectLimitAndLoop(t *testing.T) {
	f := NewFetcher()
	origin := req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")
	hop := req(t, "https://channel.example/central-dataset/gseer-dataset.ndjson.gz")
	// Go's CheckRedirect semantics: the hop to the k-th redirect carries
	// a via chain of length k (the origin first).  The policy refuses when
	// len(via) >= DefaultMaxRedirects, so hops with via lengths 1..4 are
	// inside the limit and the 5th redirect hop (len 5) is refused —
	// exactly DefaultMaxRedirects-1 redirects can be FOLLOWED.
	for n := 1; n < DefaultMaxRedirects; n++ {
		via := []*http.Request{origin}
		for i := 1; i < n; i++ {
			via = append(via, hop)
		}
		if err := f.redirectPolicy(hop, via); err != nil {
			t.Fatalf("a hop inside the limit (via len %d) must be allowed: %v", n, err)
		}
	}
	overLimit := []*http.Request{origin, hop, hop, hop, hop} // len 5 → the limit is hit
	err := f.redirectPolicy(hop, overLimit)
	if err == nil || !strings.Contains(err.Error(), "redirect limit") {
		t.Errorf("hops beyond the limit must be refused: %v", err)
	}
	// A redirect loop a→b→a→b… trips the same limit: after DefaultMaxRedirects
	// alternating hops the policy refuses with the same code.
	loop := []*http.Request{origin, hop, hop, hop, hop, hop}
	err = f.redirectPolicy(hop, loop)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_REDIRECT") {
		t.Errorf("a redirect loop must trip the redirect guard: %v", err)
	}
}

// TestRedirectRealClientFollowsTrustedChain — integration: the real
// http.Client with the policy follows a same-host redirect chain on a
// loopback http test server (the local-testing exception) and the
// final-URL validation passes.
func TestRedirectRealClientFollowsTrustedChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/step1":
			http.Redirect(w, r, "/step2", http.StatusFound)
		case "/step2":
			http.Redirect(w, r, "/central-dataset/gseer-dataset-manifest.json", http.StatusFound)
		default:
			_, _ = w.Write([]byte("manifest-body"))
		}
	}))
	t.Cleanup(srv.Close)

	f := NewFetcher()
	data, err := f.fetchBytes(context.Background(), srv.URL+"/step1", 1<<20)
	if err != nil {
		t.Fatalf("redirect chain must be followed on the same host: %v", err)
	}
	if string(data) != "manifest-body" {
		t.Errorf("unexpected body through the redirect chain: %q", string(data))
	}
}

// officialCDNResolver pins the resolution seam for the official GitHub
// release-asset CDN hostnames (public addresses — never private) plus a
// couple of look-alike hosts that must never inherit the trust.
func officialCDNResolver(t *testing.T) {
	t.Helper()
	withResolver(t, map[string][]string{
		"release-assets.githubusercontent.com":         {"93.184.216.34"},
		"objects.githubusercontent.com":                {"93.184.216.35"},
		"release-assets.githubusercontent.com.evil.io": {"93.184.216.36"},
		"evil-githubusercontent.com":                   {"93.184.216.37"},
		"githubusercontent.com":                        {"93.184.216.38"},
	})
}

// TestNewFetcherSeedsDefaultTrustedHosts — every fetcher starts with the
// official GitHub release-asset CDN hosts trusted, and mutating one
// fetcher's list never re-shapes a later fetcher (copy, not alias).
func TestNewFetcherSeedsDefaultTrustedHosts(t *testing.T) {
	officialCDNResolver(t)
	f := NewFetcher()
	for _, h := range DefaultTrustedRedirectHosts {
		if !f.trustedHost(h) {
			t.Errorf("a fresh fetcher must trust %q", h)
		}
	}
	f.TrustedRedirectHosts[0] = "hijacked.example"
	g := NewFetcher()
	if !g.trustedHost(DefaultTrustedRedirectHosts[0]) {
		t.Errorf("mutating one fetcher's list must not poison later fetchers")
	}
}

// TestDefaultTrustedHostsAllowOfficialGitHubCDN — the DEFAULT install
// follows the official channel's github.com → release-asset CDN hop
// (both the current and the legacy target) while every look-alike
// hostname stays refused (exact-host match, no suffix/wildcard trust).
func TestDefaultTrustedHostsAllowOfficialGitHubCDN(t *testing.T) {
	officialCDNResolver(t)
	f := NewFetcher()
	via := []*http.Request{req(t, config.OfficialDatasetManifestURL)}
	for _, cdn := range []string{
		"https://release-assets.githubusercontent.com/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json",
		"https://objects.githubusercontent.com/legacy/asset/path",
	} {
		if err := f.redirectPolicy(req(t, cdn), via); err != nil {
			t.Errorf("the official CDN hop must be followed by default: %v", err)
		}
	}
	for _, lookalike := range []string{
		"https://release-assets.githubusercontent.com.evil.io/payload.gz",
		"https://evil-githubusercontent.com/payload.gz",
		"https://githubusercontent.com/payload.gz",
	} {
		err := f.redirectPolicy(req(t, lookalike), via)
		if err == nil || !strings.Contains(err.Error(), "untrusted") {
			t.Errorf("look-alike host %s must stay refused: %v", lookalike, err)
		}
	}
}

// TestConfiguredListReplacesDefaultTrustedHosts — an explicitly
// configured dataset.trusted_redirect_hosts list replaces the default
// set verbatim: the GitHub CDN is no longer trusted unless listed, and
// trust is confined to the configured host.
func TestConfiguredListReplacesDefaultTrustedHosts(t *testing.T) {
	officialCDNResolver(t)
	withResolver(t, map[string][]string{"cdn.trusted.example": {"93.184.216.40"}})
	f := NewFetcher()
	f.TrustedRedirectHosts = []string{"cdn.trusted.example"}
	via := []*http.Request{req(t, "https://channel.example/central-dataset/gseer-dataset-manifest.json")}
	if err := f.redirectPolicy(req(t, "https://cdn.trusted.example/payload.gz"), via); err != nil {
		t.Errorf("the configured CDN must be allowed: %v", err)
	}
	err := f.redirectPolicy(req(t, "https://release-assets.githubusercontent.com/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Errorf("the GitHub CDN must NOT be trusted once the operator configures their own list: %v", err)
	}
}

// TestConfiguredEmptyListTrustsNothing — trust nothing is an expressible,
// honored choice: trusted_redirect_hosts: [] refuses every cross-host
// hop, including the official CDN.
func TestConfiguredEmptyListTrustsNothing(t *testing.T) {
	officialCDNResolver(t)
	f := NewFetcher()
	f.TrustedRedirectHosts = []string{}
	via := []*http.Request{req(t, config.OfficialDatasetManifestURL)}
	err := f.redirectPolicy(req(t, "https://release-assets.githubusercontent.com/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Errorf("an explicit empty trust list must refuse every cross-host hop: %v", err)
	}
}

// TestDefaultTrustedHostsNeverBypassOtherRules — trust only lifts the
// cross-host refusal: the CDN hostnames resolving into a prohibited
// range are still refused, and an HTTPS→HTTP downgrade to the CDN is
// still refused.  (Prohibited-destination and transport checks run
// BEFORE the trust check.)
func TestDefaultTrustedHostsNeverBypassOtherRules(t *testing.T) {
	withResolver(t, map[string][]string{
		"release-assets.githubusercontent.com": {"93.184.216.34", "10.0.0.8"}, // one address private
	})
	f := NewFetcher()
	via := []*http.Request{req(t, config.OfficialDatasetManifestURL)}
	err := f.redirectPolicy(req(t, "https://release-assets.githubusercontent.com/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "prohibited") {
		t.Errorf("a trusted CDN resolving to a private address must still be refused: %v", err)
	}
	err = f.redirectPolicy(req(t, "http://release-assets.githubusercontent.com/payload.gz"), via)
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("an HTTPS→HTTP downgrade to a trusted CDN must still be refused: %v", err)
	}
}

// TestRedirectRealClientOfficialCDNRedirectTLS — end-to-end with the
// real http.Client: a loopback TLS origin (standing in for
// github.com) 302-redirects to https://release-assets.githubusercontent.com
// (standing in for the CDN, with a certificate issued for that exact
// hostname and the dialer rewritten to the loopback CDN server).  The
// DEFAULT fetcher follows the hop, the TLS session is verified against
// the CDN certificate (no skip-verify anywhere), and the final-URL rule
// passes.  This is the exact hop shape the owner's WSL runtime hit.
func TestRedirectRealClientOfficialCDNRedirectTLS(t *testing.T) {
	officialCDNResolver(t)
	const cdnHost = "release-assets.githubusercontent.com"

	// CDN server with a certificate issued for the CDN hostname.
	cdnKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cdn key: %v", err)
	}
	cdnTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: cdnHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cdnHost},
		IsCA:                  true,
	}
	cdnDER, err := x509.CreateCertificate(rand.Reader, cdnTpl, cdnTpl, &cdnKey.PublicKey, cdnKey)
	if err != nil {
		t.Fatalf("cdn cert: %v", err)
	}
	cdnPool := x509.NewCertPool()
	cdnCert, err := x509.ParseCertificate(cdnDER)
	if err != nil {
		t.Fatalf("cdn cert parse: %v", err)
	}
	cdnPool.AddCert(cdnCert)
	cdnSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("manifest-body"))
	}))
	cdnSrv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cdnDER}, PrivateKey: cdnKey}}}
	cdnSrv.StartTLS()
	t.Cleanup(cdnSrv.Close)

	// Origin server (loopback TLS) that performs the github.com-style hop.
	originSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+cdnHost+"/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json", http.StatusFound)
	}))
	t.Cleanup(originSrv.Close)
	originPool := x509.NewCertPool()
	originPool.AddCert(originSrv.Certificate())

	// One transport for both hops: the dialer rewrites each hostname to
	// its loopback stand-in while TLS still validates the REAL hostname
	// against the right certificate pool.
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var target string
			var cfg *tls.Config
			switch host {
			case cdnHost:
				target = cdnSrv.Listener.Addr().String()
				cfg = &tls.Config{ServerName: cdnHost, RootCAs: cdnPool, MinVersion: tls.VersionTLS12}
			default: // the loopback origin (127.0.0.1)
				target = originSrv.Listener.Addr().String()
				cfg = &tls.Config{ServerName: "127.0.0.1", RootCAs: originPool, MinVersion: tls.VersionTLS12}
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tc, nil
		},
	}

	f := NewFetcher()
	f.Client.Transport = tr
	data, err := f.fetchBytes(context.Background(), originSrv.URL+"/central-dataset/gseer-dataset-manifest.json", 1<<20)
	if err != nil {
		t.Fatalf("the official-channel redirect hop must be followed end-to-end by the default fetcher: %v", err)
	}
	if string(data) != "manifest-body" {
		t.Errorf("unexpected body through the CDN hop: %q", string(data))
	}
}
