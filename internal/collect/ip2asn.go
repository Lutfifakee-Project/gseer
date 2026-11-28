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

// ip2asn.go — the ASN/BGP enrichment connector (v0.0.2 P1), backed by
// the public IP-to-ASN mapping community service over its DNS
// interfaces (provider identity, endpoints and terms: docs/SOURCES.md §D).
//
// WHAT IT DOES: for IP assets the operator's index already holds (seed_mode
// "index") or the operator names in config, it asks the IP-to-ASN
// DNS service for the origin ASN, prefix, country and registry,
// plus the AS name from the companion ASN interface — and writes the
// answer as an ENRICHMENT fact on that same IP asset (asn / asn_org /
// geo_country columns; raw answer lines preserved in evidence).
//
// Terms verdict — reviewed-enabled.  The service is published as a free
// community service, and volume users are asked to use the bulk or DNS
// interfaces; the register quotes the published terms verbatim.  GSEER
// uses the DNS interface (the lighter of the two),
// issues one lookup per identifier (answered lookups are cached by the
// index — re-runs dedupe at L2 and re-ask only fresh seeds), and caps
// runs through limit_per_run.  Full review: docs/SOURCES.md §D.
//
// Discovery ≠ observation: an origin-AS answer is BGP/routing publication
// data.  It says nothing about which ports answer on the address.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// Provider DNS interface bases (docs/SOURCES.md §D; overridable in
// config only for tests — production defaults are the documented ones).
const (
	ip2ASNDomainV4 = "origin.asn.cymru.com"
	ip2ASNDomainV6 = "origin6.asn.cymru.com"
	asnNameDomain  = "asn.cymru.com"
)

// ip2asnConnector enriches IP assets with origin-AS data.
type ip2asnConnector struct{}

// Kind implements Collector.
func (ip2asnConnector) Kind() string { return "ip2asn" }

// Review implements Collector (docs/SOURCES.md §D).
func (ip2asnConnector) Review() Review {
	return Review{
		Verdict: ReviewEnabled,
		Why:     "free community IP-to-ASN service over its DNS interface, conservative rates, answers cached in the index",
		DocRef:  "docs/SOURCES.md §D (ASN/BGP IP-to-ASN)",
	}
}

// Collect implements Collector: one enrichment pass over the seeds.
func (ip2asnConnector) Collect(ctx Ctx) (*Batch, error) {
	if ctx.Config.SeedMode == "index" && ctx.Config.SeedKind != "" && ctx.Config.SeedKind != "ip" {
		return nil, Fatal(fmt.Errorf("ip2asn: seed_kind %q not enrichable (want \"ip\")", ctx.Config.SeedKind))
	}
	var names []string
	var err error
	seedWalk := false
	if ctx.Config.SeedMode == "config" {
		names = ctx.Config.Seeds
	} else if ctx.IndexSeedsAfter != nil {
		// P1 (R36) seed-walk; R37: PER-FAMILY cursors.  The checkpoint
		// carries BOTH walk positions as "v4=<last v4 seed>|v6=<last v6
		// seed>" (a bare legacy value means the v4 cursor only).  Each
		// run pages the IPv4 and IPv6 halves of the corpus separately in
		// stable value order — with a single text-order cursor the v6
		// range sat unreachable behind tens of thousands of v4 values —
		// and wraps each family at its own end.  Consecutive runs enrich
		// DIFFERENT addresses in BOTH families (the DNS connector's R35
		// pattern, doubled).
		seedWalk = true
		afterV4, afterV6 := splitWalkCursor(strings.TrimSpace(ctx.Cursor))
		budget := ctx.Limit
		if budget <= 0 {
			budget = DefaultRunLimit
		}
		half := budget - budget/2
		v4names, err := walkFamily(ctx, afterV4, half, false)
		if err != nil {
			return nil, err
		}
		v6names, err := walkFamily(ctx, afterV6, budget-half, true)
		if err != nil {
			return nil, err
		}
		names = append(v4names, v6names...)
	} else {
		names, err = ctx.IndexSeeds("ip", ctx.Limit)
		if err != nil {
			return nil, err
		}
	}

	// P1 (R36) resolver fallback: on a RESTRICTED vantage the system
	// resolver may SERVFAIL whole zones (the R35 evidence: cymru zones
	// dead while example.com answers).  With no operator resolver
	// configured, the FIRST resolver-level failure (timeout/temporary —
	// NXDOMAIN is an ANSWER, never a trigger) switches the pass to the
	// built-in public resolvers; the fallback is tallied in the batch
	// notes, never silent, and the SOURCE stays Cymru.
	r := dnsResolver(ctx.Config.Resolver)
	fellBack := false
	now := time.Now().UTC()
	// ip2ASNDialTimeout bounds EVERY TXT query (R36 live evidence: a
	// restricted vantage's system resolver can blackhole a read
	// forever — the connector never relies on an unbounded transport).
	lookup := func(r *net.Resolver, name string) ([]string, error) {
		lctx, cancel := context.WithTimeout(ctx.Context, ip2ASNDialTimeout)
		defer cancel()
		return lookupTXT(lctx, r, name)
	}
	raws := make([]RawFact, 0, len(names))
	asks, hits := 0, 0
	var lookupErrs []error

	for _, seed := range names {
		if err := ctx.Context.Err(); err != nil {
			return nil, err
		}
		addr, nerr := suppress.NormalizeIP(seed)
		if nerr != nil {
			raws = append(raws, RawFact{AssetKind: "ip", Value: seed, ObservedAt: now})
			continue // pipeline dead-letters the invalid seed
		}
		asks++

		txt, qerr := lookup(r, reverseIP(addr)+"."+ip2ASNDomainOf(addr))
		if qerr != nil && !fellBack && ctx.Config.Resolver == "" && resolverLevelFailure(qerr) {
			if fr := pickFallbackResolver(lookup, reverseIP(addr)+"."+ip2ASNDomainOf(addr)); fr != nil {
				r = fr
				fellBack = true
				txt, qerr = lookup(r, reverseIP(addr)+"."+ip2ASNDomainOf(addr))
			}
		}
		if qerr != nil {
			lookupErrs = append(lookupErrs, qerr)
			continue
		}
		if len(txt) == 0 {
			continue // no route/answer published for this address
		}
		rec, perr := parseCymruOrigin(txt[0])
		if perr == nil {
			// P0 (R36) integrity: the origin service answers with the
			// longest-prefix covering route — the returned prefix MUST
			// actually contain the queried address.  A prefix that does
			// not cover it is a malformed/mis-mapped answer: audit-only,
			// never enrichment, never an invented attribution.
			if pfx, cerr := netip.ParsePrefix(rec.Prefix); cerr != nil {
				perr = fmt.Errorf("origin answer %q: prefix field: %v", rec.Raw, cerr)
			} else if ipa, aerr := netip.ParseAddr(addr); aerr != nil || !pfx.Contains(ipa) {
				perr = fmt.Errorf("origin answer %q: prefix %s does not cover %s", rec.Raw, rec.Prefix, addr)
			}
		}
		if perr != nil {
			// Malformed answer: keep it for audit, do not enrich.
			raws = append(raws, RawFact{
				AssetKind: "ip", Value: addr, ObservedAt: now, Confidence: "low",
				Extra: map[string]any{"ip2asn": map[string]any{"raw": strings.Join(txt, " | "), "parse_error": perr.Error()}},
			})
			hits++
			continue
		}

		// AS name from the companion interface (best effort — a miss
		// never blocks the ASN enrichment itself).
		asName := ""
		if rec.ASN > 0 {
			nameTXT, nerr := lookup(r, fmt.Sprintf("AS%d.%s", rec.ASN, asnNameDomain))
			if nerr == nil && len(nameTXT) > 0 {
				asName = parseCymruASName(nameTXT[0])
			}
		}

		hits++
		raws = append(raws, RawFact{
			AssetKind:  "ip",
			Value:      addr,
			ObservedAt: now,
			Confidence: "medium", // routing data is point-in-time
			ASN:        rec.ASN,
			ASNOrg:     asName,
			GeoCountry: rec.Country,
			Extra: map[string]any{
				"ip2asn": map[string]any{
					"asn": rec.ASN, "prefix": rec.Prefix, "country": rec.Country,
					"registry": rec.Registry, "allocated": rec.Allocated, "raw": rec.Raw,
				},
			},
		})
	}

	// Every lookup failed → only a TRANSPORT failure is retryable.  An
	// all-NXDOMAIN pass is an honest ZERO-HIT batch (the source simply
	// publishes nothing for these addresses — never fabricated, never
	// an error); a resolver-level total failure stays a hard error.
	resolverDown := 0
	for _, lerr := range lookupErrs {
		if resolverLevelFailure(lerr) {
			resolverDown++
		}
	}
	if asks > 0 && hits == 0 && len(lookupErrs) == asks && resolverDown == len(lookupErrs) {
		return nil, fmt.Errorf("ip2asn: all %d lookups failed (resolver %q): %v",
			asks, resolverLabel(ctx.Config.Resolver), lookupErrs[0])
	}
	notes := map[string]int{"asks": asks, "hits": hits, "seeds": len(names)}
	if fellBack {
		notes["resolver_fallback"] = 1
	}
	var lastV4, lastV6 string
	if seedWalk {
		for _, n := range names {
			if strings.Contains(n, ":") {
				lastV6 = n
			} else {
				lastV4 = n
			}
		}
		notes["v4_seeds"] = len(names) - countV6(names)
		notes["v6_seeds"] = countV6(names)
	}
	batch := &Batch{Raws: raws, Done: true, Notes: notes}
	if seedWalk {
		if len(lastV4) > 0 || len(lastV6) > 0 {
			// The per-family walk positions = the LAST seed seen in each
			// family this pass (enriched or not — coverage advances by
			// value).
			batch.Cursor = "v4=" + lastV4 + "|v6=" + lastV6
		} else if strings.TrimSpace(ctx.Cursor) != "" {
			batch.Cursor = strings.TrimSpace(ctx.Cursor)
		}
	}
	return batch, nil
}

// splitWalkCursor parses the R37 composite walk cursor.  A bare legacy
// value (R36 single-cursor format) is the v4 position; the v6 walk then
// starts fresh.  Returns the (v4, v6) positions.
func splitWalkCursor(cursor string) (string, string) {
	if i := strings.Index(cursor, "|"); i >= 0 {
		v4 := strings.TrimPrefix(cursor[:i], "v4=")
		v6 := strings.TrimPrefix(cursor[i+1:], "v6=")
		return v4, v6
	}
	return cursor, ""
}

// walkFamily pages ONE address family's index slice: the seeds strictly
// after `after` whose TEXT shape matches the family (':' present for
// IPv6), wrapping to the start of the corpus when the family page is
// exhausted.  lastSeed is returned via the out parameter so the caller
// can persist the family cursor even when the page straddles both
// families' value ranges.
func walkFamily(ctx Ctx, after string, budget int, v6 bool) ([]string, error) {
	// Preferred path (R37): a family-aware index query — the walk
	// never depends on text-order luck to reach the other family.
	if ctx.IndexSeedsFamilyAfter != nil {
		names, err := ctx.IndexSeedsFamilyAfter("ip", after, budget, v6)
		if err == nil && len(names) == 0 && after != "" {
			names, err = ctx.IndexSeedsFamilyAfter("ip", "", budget, v6) // wrap
		}
		return names, err
	}
	filter := func(raw []string) []string {
		family := make([]string, 0, budget)
		for _, n := range raw {
			if strings.Contains(n, ":") != v6 {
				continue
			}
			family = append(family, n)
			if len(family) == budget {
				break
			}
		}
		return family
	}
	names, err := ctx.IndexSeedsAfter("ip", after, budget*walkFamilyScanFactor)
	if err != nil {
		return nil, err
	}
	family := filter(names)
	// Wrap on a FAMILY-empty page (not a page-empty one): the text
	// order interleaves both families, so a page can hold only the
	// other family's values while this family's slice is exhausted.
	if len(family) == 0 && after != "" {
		wrapped, werr := ctx.IndexSeedsAfter("ip", "", budget*walkFamilyScanFactor)
		if werr != nil {
			return nil, werr
		}
		family = filter(wrapped)
	}
	return family, nil
}

// countV6 counts the IPv6 seeds in a walk page (':' shape test).
func countV6(names []string) int {
	n := 0
	for _, x := range names {
		if strings.Contains(x, ":") {
			n++
		}
	}
	return n
}

// walkFamilyScanFactor widens the family page scan so a family slice
// can be filled even when the text order interleaves both families
// heavily (the v4 and v6 value ranges interleave in TEXT sort order).
const walkFamilyScanFactor = 4

// resolverLevelFailure reports whether a TXT lookup error means the
// RESOLVER PATH is broken (timeout / temporary / server misbehaving) —
// as opposed to an authoritative answer like NXDOMAIN (IsNotFound).
func resolverLevelFailure(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	return false
}

// pickFallbackResolver probes the built-in public resolvers with the
// failing query itself and returns the first one that answers (nil when
// none does — the pass then keeps its original errors).
func pickFallbackResolver(lookup func(*net.Resolver, string) ([]string, error), name string) *net.Resolver {
	for _, addr := range []string{"8.8.8.8", "1.1.1.1"} {
		r := dnsResolver(addr)
		if _, err := lookup(r, name); err == nil {
			return r
		}
	}
	return nil
}

// ip2ASNDialTimeout is the per-query transport deadline (see lookup).
const ip2ASNDialTimeout = 5 * time.Second

// cymruOrigin is one parsed origin-AS answer.
type cymruOrigin struct {
	ASN       int
	Prefix    string
	Country   string
	Registry  string
	Allocated string
	Raw       string
}

// parseCymruOrigin parses the canonical IP-to-ASN TXT format
// "64500 | 203.0.113.0/24 | US | arin | 2002-04-23" (fields may vary in
// count across responses; the first four are the contract).
func parseCymruOrigin(line string) (cymruOrigin, error) {
	fields := strings.Split(line, "|")
	trim := func(i int) string {
		if i < len(fields) {
			return strings.TrimSpace(fields[i])
		}
		return ""
	}
	out := cymruOrigin{Raw: line, Prefix: trim(1), Country: trim(2), Registry: trim(3), Allocated: trim(4)}
	asn, err := strconv.Atoi(trim(0))
	if err != nil {
		return out, fmt.Errorf("origin answer %q: ASN field: %v", line, err)
	}
	if asn <= 0 || asn > 4294967295 {
		return out, fmt.Errorf("origin answer %q: ASN %d out of range", line, asn)
	}
	out.ASN = asn
	if out.Prefix == "" {
		return out, fmt.Errorf("origin answer %q: empty prefix field", line)
	}
	return out, nil
}

// parseCymruASName extracts the AS name from the AS-name DNS
// interface's TXT answer defensively.  The documented live format is
// FIVE pipe-separated fields (verified against the production service
// 2026-11):
//
//	"AS64500 | US | arin | 2000-03-30 | EXAMPLE-AS - Example Org, US"
//	  ASN    | CC | registry | allocated | AS NAME
//
// so the name is the FIFTH field.  Anything else — fewer fields, an
// empty name — returns "" (the caller treats the name as best-effort
// enrichment and never blocks the ASN itself on it).
func parseCymruASName(line string) string {
	fields := strings.Split(line, "|")
	if len(fields) < 5 {
		return ""
	}
	return strings.TrimSpace(fields[4])
}

// ip2ASNDomainOf picks the v4/v6 interface by address family.
func ip2ASNDomainOf(addr string) string {
	if isIPv6(addr) {
		return ip2ASNDomainV6
	}
	return ip2ASNDomainV4
}

// reverseIP renders the address in the DNS-name order the IP-to-ASN
// interfaces expect: IPv4 octets reversed ("203.0.113.7" →
// "7.113.0.203"); IPv6 nibbles reversed (RFC 4291 §2.2 ip6.arpa order).
func reverseIP(addr string) string {
	if isIPv6(addr) {
		return reverseIPv6(addr)
	}
	parts := strings.Split(addr, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func isIPv6(addr string) bool { return strings.Contains(addr, ":") }

// reverseIPv6 expands the address and reverses its 32 nibbles
// ("2001:db8::1" → "1.0.0.….2.0.0.2"), the order ip6.arpa-style lookups
// expect WITHOUT the .ip6.arpa suffix (the interface domain supplies it).
func reverseIPv6(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	b := ip.To16()
	if b == nil {
		return ""
	}
	// Nibbles, reversed: low nibble of last byte first; rendered as hex
	// digits (nibbles 10-15 are letters — '0'+n would emit control-range
	// garbage like ':' and ';').
	const hexDigits = "0123456789abcdef"
	nibbles := make([]byte, 0, 32)
	for i := len(b) - 1; i >= 0; i-- {
		nibbles = append(nibbles, b[i]&0x0f, b[i]>>4)
	}
	out := make([]byte, 0, 63)
	for i, n := range nibbles {
		if i > 0 {
			out = append(out, '.')
		}
		out = append(out, hexDigits[n])
	}
	return string(out)
}

// lookupTXT is the seam tests fake: one TXT query through r.
var lookupTXT = func(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
	return r.LookupTXT(ctx, name)
}

func init() { register(ip2asnConnector{}) }
