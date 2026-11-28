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

package collect

// pdns.go — the passive-DNS connector (v0.3.3), the hostname-history
// layer that complements the forward `dns` connector's live answers.
//
// WHAT IT DOES: for domains the OPERATOR names (seed_mode "config") or
// already holds in the index (seed_mode "index"), it queries a public
// passive-DNS-style dataset and records the HOSTNAMES that have
// historically been published under the domain:
//
//   - provider "hackertarget" (default): the hostsearch API answers
//     "hostname,address" lines — published resolution pairs.
//   - provider "wayback": the Wayback Machine CDX index answers the
//     URLs archived under a domain wildcard — published hostname
//     history (no addresses; name-only evidence).
//
// WHAT IT NEVER DOES: no brute-force enumeration of subdomains, no
// guessing of names beyond what the provider answered, no resolution
// of the discovered names (that is the operator's explicit `dns`
// connector's job on its own seeds).  The seed list bounds the queries;
// the provider answers bound the facts.
//
// Discovery ≠ observation (P1 contract 3): a published hostname proves
// a NAME existed — it is NOT evidence that any service answered there,
// and the provider's historical address lines are recorded as evidence
// strings, not as live-reachability facts.  No service rows are
// produced.
//
// Terms verdict — reviewed-enabled.  Both providers publish free,
// key-less, rate-limited public interfaces; the operator names every
// query (one per seed), the shared client caps the rate and the body
// size, and answers are recorded with their lookup time (observed_at is
// when GSEER saw the publication, never the provider's historical
// time).  Full review: docs/SOURCES.md §J (Passive DNS).

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// Provider endpoints (docs/SOURCES.md §P; overridable in config only for
// tests — production defaults are the documented public interfaces).
const (
	pdnsHackertargetEndpoint = "https://api.hackertarget.com/hostsearch/"
	pdnsWaybackEndpoint      = "https://web.archive.org/cdx/search/cdx"
	pdnsWaybackDefaultLimit  = 500
)

// pdnsConnector records published hostname history for operator-named
// domains.
type pdnsConnector struct{}

// Kind implements Collector.
func (pdnsConnector) Kind() string { return "pdns" }

// Review implements Collector (docs/SOURCES.md §P).
func (pdnsConnector) Review() Review {
	return Review{
		Verdict: ReviewEnabled,
		Why:     "public key-less passive-DNS-style datasets (published hostname/resolution history); the operator names every query, the shared client caps rate and body size, answers are recorded as publication facts",
		DocRef:  "docs/SOURCES.md §J (Passive DNS)",
	}
}

// Collect implements Collector: one provider pass over the seeds.
func (pdnsConnector) Collect(ctx Ctx) (*Batch, error) {
	domains, err := seeds(ctx, "domain")
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return &Batch{Done: true, Notes: map[string]int{"seeds": 0, "hosts": 0}}, nil
	}

	provider := strings.ToLower(strings.TrimSpace(ctx.Config.Provider))
	if provider == "" {
		provider = "hackertarget"
	}
	endpoint := ctx.Config.Endpoint
	var fetch func(seed string) ([]RawFact, error)
	switch provider {
	case "hackertarget":
		if endpoint == "" {
			endpoint = pdnsHackertargetEndpoint
		}
		fetch = func(seed string) ([]RawFact, error) {
			return pdnsHackertarget(ctx, endpoint, seed)
		}
	case "wayback":
		if endpoint == "" {
			endpoint = pdnsWaybackEndpoint
		}
		fetch = func(seed string) ([]RawFact, error) {
			return pdnsWayback(ctx, endpoint, seed, ctx.Config.LimitPerRun)
		}
	default:
		return nil, Fatal(fmt.Errorf("pdns: unknown provider %q (want \"hackertarget\" or \"wayback\")", ctx.Config.Provider))
	}

	if ctx.Client == nil {
		return nil, Fatal(fmt.Errorf("pdns: the run's HTTP client is missing (the runner wires it)"))
	}

	seen := map[string]bool{} // hostname dedupe across seeds in one pass
	var raws []RawFact
	var seedErrs []error
	lookups, hosts := 0, 0
	for _, domain := range domains {
		lookups++
		facts, err := fetch(domain)
		if err != nil {
			seedErrs = append(seedErrs, err)
			continue // one failed seed must not sink the others' answers
		}
		for _, raw := range facts {
			if seen[raw.Value] {
				continue
			}
			seen[raw.Value] = true
			raws = append(raws, raw)
			hosts++
		}
	}
	if len(seedErrs) == len(domains) {
		return nil, fmt.Errorf("pdns: all %d seed lookups failed (provider %q): %v",
			len(seedErrs), provider, seedErrs[0])
	}
	return &Batch{
		Raws: raws,
		Done: true, // point lookups: one batch per pass, no pagination
		Notes: map[string]int{
			"lookups": lookups, "hosts": hosts, "seeds": len(domains),
			"provider_" + provider: hosts,
		},
	}, nil
}

// pdnsHackertarget asks the hostsearch API for one domain and turns the
// "hostname,address" lines into hostname facts.  A line without a comma
// is the provider's free-tier message (an error), never a hostname.
func pdnsHackertarget(ctx Ctx, endpoint, domain string) ([]RawFact, error) {
	q := endpoint + "?q=" + url.QueryEscape(domain)
	body, err := ctx.Client.Get(ctx.Context, q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("pdns: read hackertarget answer for %q: %v", domain, err)
	}
	now := nowOr(ctx)
	var out []RawFact
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, addr, ok := strings.Cut(line, ",")
		name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
		if !ok || name == "" || addr == "" || strings.Contains(addr, "/") {
			return nil, fmt.Errorf("pdns: hackertarget answered an error for %q: %.120s (the free tier is rate-limited; raise the run interval or reduce the seeds)", domain, line)
		}
		out = append(out, RawFact{
			AssetKind:  "hostname",
			Value:      name,
			ObservedAt: now,
			Confidence: "medium",
			Extra: map[string]any{"pdns": map[string]any{
				"provider": "hackertarget", "query": domain, "address": addr,
			}},
		})
	}
	return out, nil
}

// pdnsWayback asks the CDX index for the URLs archived under a domain
// wildcard and turns every archived URL's hostname into name-only
// evidence.
func pdnsWayback(ctx Ctx, endpoint, domain string, limitPerRun int) ([]RawFact, error) {
	limit := pdnsWaybackDefaultLimit
	if limitPerRun > 0 && limitPerRun < limit {
		limit = limitPerRun
	}
	q := fmt.Sprintf("%s?url=%s&output=json&fl=original&collapse=urlkey&limit=%d",
		endpoint, url.QueryEscape("*."+domain), limit)
	var rows [][]string
	if err := ctx.Client.GetJSON(ctx.Context, q, &rows); err != nil {
		return nil, fmt.Errorf("pdns: decode wayback answer for %q: %v", domain, err)
	}
	now := nowOr(ctx)
	var out []RawFact
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // header row ["original"] or a malformed empty row
		}
		raw := strings.TrimSpace(row[0])
		if raw == "" {
			continue
		}
		u, perr := url.Parse(raw)
		if perr != nil || u.Hostname() == "" {
			out = append(out, RawFact{
				AssetKind:  "hostname",
				Value:      raw, // an archived path or opaque entry: kept verbatim for the dead-letter path
				ObservedAt: now,
				Confidence: "medium",
				Extra: map[string]any{"pdns": map[string]any{
					"provider": "wayback", "query": domain, "original": raw,
				}},
			})
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		out = append(out, RawFact{
			AssetKind:  "hostname",
			Value:      host,
			ObservedAt: now,
			Confidence: "medium",
			Extra: map[string]any{"pdns": map[string]any{
				"provider": "wayback", "query": domain, "original": raw,
			}},
		})
	}
	return out, nil
}

// nowOr returns ctx.Now (injectable for tests) or time.Now.
func nowOr(ctx Ctx) time.Time {
	if ctx.Now != nil {
		return ctx.Now()
	}
	return time.Now()
}

func init() { register(pdnsConnector{}) }
