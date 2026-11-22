// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// redirect.go — R4 P0-5: redirect security for the dataset fetcher.
//
// The default http.Client follows up to 10 redirects blindly: an
// HTTPS→HTTP downgrade, a bounce to a private address, or a bounce to
// an untrusted host would all be followed silently — every hop is
// network activity the operator never asked for, and on a non-loopback
// http hop it is also a plaintext credential surface.  The policy below
// validates EVERY hop (http.Client.CheckRedirect):
//
//  1. LIMIT       — at most DefaultMaxRedirects hops (then refuse).
//  2. NO DOWNGRADE— an https origin is never redirected to plain http,
//     whatever the target.  Plain http hops are accepted only when the
//     ORIGIN was plain http AND both endpoints are loopback hosts (the
//     same rule ValidateManifestURL applies to the manifest URL —
//     local testing support, not a production path).
//  3. NO PROHIBITED DESTINATIONS on a cross-host hop: loopback, RFC1918
//     private, CGNAT (100.64/10), link-local, unspecified, multicast,
//     and benchmark (198.18/15) ranges — checked on the literal IP AND
//     on every address a hostname resolves to (fail closed: a
//     cross-host target that does not resolve is refused too).
//  4. CROSS-HOST requires explicit trust: a hop to a different host is
//     refused unless that host is in Fetcher.TrustedRedirectHosts
//     (config: dataset.trusted_redirect_hosts) — legitimate trusted CDN
//     delivery stays possible, everything else fails closed.
//     Same-host hops skip the destination checks (the operator chose
//     that origin), but still obey 1 and 2.
//  5. FINAL URL   — the response's final URL is re-validated after the
//     fetch (scheme rule + prohibited destinations), independent of the
//     per-hop policy.
//
// Credential hygiene: the fetcher never sends authentication headers at
// all, so there is nothing to leak on any hop; the redactURL discipline
// keeps userinfo out of error output.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultMaxRedirects bounds one dataset fetch's redirect chain.
const DefaultMaxRedirects = 5

// DefaultTrustedRedirectHosts are the GitHub release-asset CDN hosts the
// official central-dataset channel (config.OfficialDatasetManifestURL,
// a github.com release download) is legitimately redirected to: the
// current 302 target (release-assets.githubusercontent.com) and the
// legacy asset host (objects.githubusercontent.com).  NewFetcher seeds
// every fetcher with these so the DEFAULT install can follow the
// official channel's redirect out of the box; an explicit
// dataset.trusted_redirect_hosts list REPLACES the set wholesale
// (verbatim, including an empty list = trust nothing) and the match is
// exact-hostname (EqualFold, no wildcards).  Everything else stays
// fail-closed: trust never bypasses the per-hop transport rules, the
// prohibited-destination check, the final-URL re-validation, or the
// signature/checksum verification of what is actually downloaded.
var DefaultTrustedRedirectHosts = []string{
	"release-assets.githubusercontent.com",
	"objects.githubusercontent.com",
}

// maxRedirects returns the effective redirect limit.
func (f *Fetcher) maxRedirects() int {
	if f.MaxRedirects > 0 {
		return f.MaxRedirects
	}
	return DefaultMaxRedirects
}

// trustedHost reports whether host is explicitly trusted for cross-host
// redirects (case-insensitive; ports are not part of the trust match).
func (f *Fetcher) trustedHost(host string) bool {
	for _, h := range f.TrustedRedirectHosts {
		if strings.EqualFold(strings.TrimSpace(h), host) {
			return true
		}
	}
	return false
}

// redirectPolicy is the http.Client.CheckRedirect implementation: it
// returns an error to refuse a hop (Go aborts the request, exposing the
// error through url.Error / ErrUseLastResponse absence).
func (f *Fetcher) redirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL
	if len(via) >= f.maxRedirects() {
		return fmt.Errorf("E_DATASET_REDIRECT: redirect limit (%d) exceeded at %s", f.maxRedirects(), redactURL(req.URL.String()))
	}
	// 2. Transport rules (every hop, same-host or not).
	if req.URL.Scheme == "http" && origin.Scheme == "https" {
		return fmt.Errorf("E_DATASET_REDIRECT: HTTPS-to-HTTP downgrade refused: %s -> %s",
			redactURL(origin.String()), redactURL(req.URL.String()))
	}
	if req.URL.Scheme == "http" {
		// Plain http is a loopback-testing-only transport (mirrors
		// ValidateManifestURL): both ends must be loopback.
		if !isLoopbackHost(origin.Hostname()) || !isLoopbackHost(req.URL.Hostname()) {
			return fmt.Errorf("E_DATASET_REDIRECT: plain http is accepted only between loopback hosts: %s -> %s",
				redactURL(origin.String()), redactURL(req.URL.String()))
		}
	}
	// 3+4. Destination rules apply to CROSS-HOST hops only (a same-host
	// hop is the origin the operator already chose).
	if !sameHostname(origin, req.URL) {
		if err := rejectProhibitedDestination(req.URL); err != nil {
			return err
		}
		if !f.trustedHost(req.URL.Hostname()) {
			return fmt.Errorf("E_DATASET_REDIRECT: cross-host redirect to untrusted host %q refused (same fetch started at %s) — allow a trusted CDN explicitly via config dataset.trusted_redirect_hosts",
				req.URL.Hostname(), redactURL(origin.String()))
		}
	}
	return nil
}

// validateFinalResponse re-validates the FINAL response URL after the
// fetch: the transport rule (https, or loopback http) plus — for a
// cross-host final destination — the prohibited-destination check.  The
// per-hop policy already enforced both; this is the independent last
// gate the audit requires.
func validateFinalResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return fmt.Errorf("E_DATASET_REDIRECT: response carries no final URL")
	}
	u := resp.Request.URL
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return fmt.Errorf("E_DATASET_REDIRECT: final URL %s violates the transport rule (https, or loopback http for local testing)", redactURL(u.String()))
	}
	return nil
}

// rejectProhibitedDestination refuses a URL whose host is a loopback,
// private, CGNAT, link-local, unspecified, multicast, or benchmark
// address — as a literal IP or as ANY address its hostname resolves to.
// A cross-host target that cannot be resolved is refused (fail closed).
func rejectProhibitedDestination(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("E_DATASET_REDIRECT: redirect target has no host: %s", redactURL(u.String()))
	}
	ips, rerr := resolveHostIPsFn(host)
	if rerr != nil {
		return fmt.Errorf("E_DATASET_REDIRECT: redirect target %q could not be resolved (refused, fail closed): %v", host, rerr)
	}
	for _, ip := range ips {
		if prohibitedIP(ip) {
			return fmt.Errorf("E_DATASET_REDIRECT: redirect target %q resolves to a prohibited address (%s) — loopback/private/link-local/multicast ranges are never followed: %s",
				host, ip, redactURL(u.String()))
		}
	}
	return nil
}

// resolveHostIPsFn is the resolution seam (tests inject deterministic
// addresses; production uses the real resolver below).
var resolveHostIPsFn = resolveHostIPs

// resolveHostIPs returns the literal IP when host IS an address,
// otherwise resolves it with a short timeout.
func resolveHostIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// prohibitedIP reports whether ip is in a range a dataset fetch must
// never follow a redirect to.
func prohibitedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// CGNAT 100.64.0.0/10 and the benchmark range 198.18.0.0/15 are not
	// covered by net.IP's helpers.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		if v4[0] == 198 && v4[1] >= 18 && v4[1] <= 19 {
			return true
		}
	}
	return false
}

// sameHostname compares two URLs' hostnames case-insensitively (ports
// and schemes may differ; the host is the identity that matters here).
func sameHostname(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname())
}
