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

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

// ip2asn_test.go — the IP-to-ASN parser tests.  The quoted TXT lines are
// the PRODUCTION format captured live from the provider's documented
// origin/AS-name DNS interfaces (docs/SOURCES.md §D) in 2026-11 and keep
// their real field shapes; they are fixtures of the wire format, not
// observations.

// TestParseCymruASNameLiveFormat pins the five-field AS-name format:
// "AS{n} | CC | registry | allocated | AS NAME" — the name is field 5.
// (Regression: an earlier parser read field 3 and stored the REGISTRY —
// "arin" — as the AS organisation.)
func TestParseCymruASNameLiveFormat(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "AS15169 live answer",
			line: "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US",
			want: "GOOGLE - Google LLC, US",
		},
		{
			name: "AS13335 live answer",
			line: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US",
			want: "CLOUDFLARENET - Cloudflare, Inc., US",
		},
		{
			name: "name is exactly field 5 (extra fields are not part of the format)",
			line: "64500 | US | arin | 2002-04-23 | EXAMPLE-AS - Example, US | extra",
			want: "EXAMPLE-AS - Example, US",
		},
		{
			name: "empty name field",
			line: "64500 | US | arin | 2002-04-23 | ",
			want: "",
		},
		{
			name: "registry-only three-field shape yields empty (never 'arin')",
			line: "15169 | US | arin",
			want: "",
		},
		{
			name: "two-field shape yields empty",
			line: "15169 | US",
			want: "",
		},
		{
			name: "empty input yields empty",
			line: "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCymruASName(tc.line); got != tc.want {
				t.Fatalf("parseCymruASName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// TestParseCymruOriginFixtures covers the canonical origin answer shapes:
// five fields with the allocation date, and the documented four-field
// variant without one.
func TestParseCymruOriginFixtures(t *testing.T) {
	t.Run("five-field origin line", func(t *testing.T) {
		rec, err := parseCymruOrigin("15169 | 8.8.8.0/24 | US | arin | 2023-12-28")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.ASN != 15169 || rec.Prefix != "8.8.8.0/24" || rec.Country != "US" || rec.Registry != "arin" || rec.Allocated != "2023-12-28" {
			t.Fatalf("parsed record wrong: %+v", rec)
		}
	})
	t.Run("four-field origin line (no allocation date)", func(t *testing.T) {
		rec, err := parseCymruOrigin("64500 | 203.0.113.0/24 | US | arin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rec.ASN != 64500 || rec.Prefix != "203.0.113.0/24" || rec.Country != "US" || rec.Registry != "arin" || rec.Allocated != "" {
			t.Fatalf("parsed record wrong: %+v", rec)
		}
	})
	t.Run("non-numeric ASN rejected", func(t *testing.T) {
		if _, err := parseCymruOrigin("not-an-asn | 203.0.113.0/24 | US | arin"); err == nil {
			t.Fatal("expected an error for a non-numeric ASN field")
		}
	})
	t.Run("empty prefix rejected", func(t *testing.T) {
		if _, err := parseCymruOrigin("64500 |  | US | arin"); err == nil {
			t.Fatal("expected an error for an empty prefix field")
		}
	})
}

// TestReverseIPFixtures pins the reverse-DNS label orders both IP-to-ASN
// interfaces expect (RFC 4291 §2.2 nibble order for IPv6).
func TestReverseIPFixtures(t *testing.T) {
	v4 := reverseIP("8.8.8.8")
	if v4 != "8.8.8.8" {
		t.Fatalf("reverseIP(8.8.8.8) = %q, want \"8.8.8.8\"", v4)
	}
	v4b := reverseIP("203.0.113.7")
	if v4b != "7.113.0.203" {
		t.Fatalf("reverseIP(203.0.113.7) = %q, want \"7.113.0.203\"", v4b)
	}
	v6 := reverseIP("2001:db8::1")
	// 2001:0db8:0000:0000:0000:0000:0000:0001 reversed nibble order.
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
	if v6 != want {
		t.Fatalf("reverseIP(2001:db8::1) = %q, want %q", v6, want)
	}
}

// TestIP2ASNConnectorResolverFallback — R36 P1: on a restricted vantage
// the system resolver SERVFAILs whole zones (the R35 evidence).  With no
// configured resolver, the first resolver-level failure switches the
// pass to the built-in public resolvers; the fallback is tallied
// (notes resolver_fallback) and the enrichment still lands.
func TestIP2ASNConnectorResolverFallback(t *testing.T) {
	orig := lookupTXT
	t.Cleanup(func() { lookupTXT = orig })
	origin := "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
	lookupTXT = func(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
		if r == net.DefaultResolver {
			return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
		}
		if strings.Contains(name, ".origin.asn.cymru.com") {
			return []string{origin}, nil
		}
		return []string{"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"}, nil
	}

	c := ctxFor(SourceConfig{SeedMode: "config", Seeds: []string{"8.8.8.8"}})
	batch, err := (ip2asnConnector{}).Collect(c)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if batch.Notes["resolver_fallback"] != 1 {
		t.Fatalf("notes resolver_fallback = %d, want 1", batch.Notes["resolver_fallback"])
	}
	if batch.Notes["hits"] != 1 {
		t.Fatalf("hits = %d, want 1 (the fallback must still enrich)", batch.Notes["hits"])
	}
	if len(batch.Raws) != 1 || batch.Raws[0].ASN != 15169 {
		t.Fatalf("fact = %+v, want asn 15169", batch.Raws)
	}
	if batch.Raws[0].Extra["ip2asn"].(map[string]any)["prefix"] != "8.8.8.0/24" {
		t.Fatalf("provenance prefix missing: %+v", batch.Raws[0].Extra)
	}

	// NXDOMAIN is an ANSWER: it must NEVER trigger the fallback.
	lookupTXT = func(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	batch, err = (ip2asnConnector{}).Collect(c)
	if err != nil {
		t.Fatalf("collect (nxdomain): %v", err)
	}
	if batch.Notes["resolver_fallback"] != 0 {
		t.Fatal("NXDOMAIN triggered the fallback — authoritative answers must not")
	}
}

// TestIP2ASNConnectorSeedWalk — R36 P1 / R37 per-family cursors: index
// mode pages the IPv4 and IPv6 halves of the corpus separately, each
// AFTER its own checkpoint position in stable value order, each wrapping
// at its own end; the checkpoint carries both positions.
func TestIP2ASNConnectorSeedWalk(t *testing.T) {
	orig := lookupTXT
	t.Cleanup(func() { lookupTXT = orig })
	lookupTXT = func(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
		return []string{"13335 | 1.1.1.0/24 | US | arin | 2010-07-14"}, nil
	}
	// The index's TEXT value order interleaves both families.
	corpus := []string{"1.1.1.1", "1.2.3.4", "2001:4860::8", "2.2.2.2", "3.3.3.3", "2606:4700::1", "4.4.4.4"}
	ctxForWalk := func(cursor string, limit int) Ctx {
		c := ctxFor(SourceConfig{SeedMode: "index", SeedKind: "ip"})
		c.Limit = limit
		c.Cursor = cursor
		c.IndexSeeds = func(kind string, limit int) ([]string, error) {
			return nil, fmt.Errorf("seed-walk must not use the freshest-first path")
		}
		c.IndexSeedsAfter = func(kind, after string, limit int) ([]string, error) {
			out := []string{}
			started := after == ""
			for _, v := range corpus {
				if !started {
					if v == after {
						started = true
					}
					continue
				}
				out = append(out, v)
				if len(out) == limit {
					break
				}
			}
			return out, nil
		}
		return c
	}

	// Run 1 (budget 4 → 2 v4 + 2 v6 seeds): the v4 walk takes the first
	// two v4 values; the v6 walk takes the first two v6 values.
	first, err := (ip2asnConnector{}).Collect(ctxForWalk("", 4))
	if err != nil {
		t.Fatalf("walk 1: %v", err)
	}
	if first.Cursor != "v4=1.2.3.4|v6=2606:4700::1" {
		t.Fatalf("walk 1 cursor = %q, want v4=1.2.3.4|v6=2606:4700::1", first.Cursor)
	}
	if first.Notes["v4_seeds"] != 2 || first.Notes["v6_seeds"] != 2 {
		t.Fatalf("walk 1 notes = %v, want 2 v4 + 2 v6 seeds", first.Notes)
	}

	// Run 2: both families advance past their own positions.
	second, err := (ip2asnConnector{}).Collect(ctxForWalk(first.Cursor, 4))
	if err != nil {
		t.Fatalf("walk 2: %v", err)
	}
	if second.Cursor != "v4=3.3.3.3|v6=2606:4700::1" {
		t.Fatalf("walk 2 cursor = %q, want v4=3.3.3.3|v6=2606:4700::1 (the v6 walk wrapped to refill its page)", second.Cursor)
	}

	// Run 3: the v4 family wraps at its end; the v6 position holds.
	third, err := (ip2asnConnector{}).Collect(ctxForWalk(second.Cursor, 4))
	if err != nil {
		t.Fatalf("walk 3 (wrap): %v", err)
	}
	if third.Cursor != "v4=4.4.4.4|v6=2606:4700::1" {
		t.Fatalf("walk 3 cursor = %q, want v4=4.4.4.4|v6=2606:4700::1 (each family advanced independently)", third.Cursor)
	}

	// A legacy bare cursor (R36 format) means the v4 position only; the
	// v6 walk starts fresh.
	legacy, err := (ip2asnConnector{}).Collect(ctxForWalk("2.2.2.2", 4))
	if err != nil {
		t.Fatalf("legacy cursor walk: %v", err)
	}
	if legacy.Cursor != "v4=4.4.4.4|v6=2606:4700::1" {
		t.Fatalf("legacy cursor walk = %q, want v4 continuation + fresh v6 walk", legacy.Cursor)
	}
}

// TestIP2ASNConnectorRejectsNonCoveringPrefix — R36 P0 integrity: the
// origin service answers with the longest-prefix covering route; an
// answer whose prefix does NOT contain the queried address is a
// mis-mapped/malformed answer — audit-only (low confidence), never an
// invented ASN attribution, never an enrichment fact.
func TestIP2ASNConnectorRejectsNonCoveringPrefix(t *testing.T) {
	orig := lookupTXT
	t.Cleanup(func() { lookupTXT = orig })
	// 8.8.8.8 asked, but the answer claims 9.9.9.0/24 — does not cover.
	lookupTXT = func(ctx context.Context, r *net.Resolver, name string) ([]string, error) {
		return []string{"15169 | 9.9.9.0/24 | US | arin | 2023-12-28"}, nil
	}
	c := ctxFor(SourceConfig{SeedMode: "config", Seeds: []string{"8.8.8.8"}})
	batch, err := (ip2asnConnector{}).Collect(c)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(batch.Raws) != 1 || batch.Raws[0].ASN != 0 {
		t.Fatalf("fact = %+v, want zero ASN (audit-only)", batch.Raws)
	}
	if batch.Raws[0].Confidence != "low" {
		t.Fatalf("confidence = %q, want low (audit path)", batch.Raws[0].Confidence)
	}
	extra := batch.Raws[0].Extra["ip2asn"].(map[string]any)
	if extra["parse_error"] == nil {
		t.Fatalf("evidence = %+v, want the containment parse_error for audit", extra)
	}
	if batch.Notes["hits"] != 1 {
		t.Fatalf("hits = %d, want 1 (the audit row still counts as a seen answer)", batch.Notes["hits"])
	}
}
