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

package searchlite

// mastery_test.go — the R3 "search must be genuinely mature" proof, on
// the personal (SQLite) path, over a labeled corpus: field coverage
// (ip/cidr/domain/hostname/asn/port/service/technology), operator
// combinations, exact vs prefix matching with relevance ordering,
// cross-entity joins (domain → its hostnames), pagination without
// dup/miss, sorting, and limits.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// seedMasteryCorpus builds a labeled corpus:
//
//	198.51.100.7 — 443/https nginx, 80/http apache (title), 22/ssh openssh
//	                ASN 64500 / "Bench Telecom" / country US
//	198.51.100.8 — 443/https nginx-core, ASN 64501 / "Bench Cloud" / DE
//	web1.bench.example (hostname of bench.example)
//	mail.bench.example (hostname of bench.example)
//	bench.example    (domain)
func seedMasteryCorpus(t *testing.T) (*sql.DB, *Service) {
	t.Helper()
	dir := t.TempDir()
	res, err := sqlstore.Open(filepath.Join(dir, "gseer.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlstore.Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := sqlstore.NewStore(res.DB)
	src, err := store.EnsureSource(context.Background(), "mastery", "fixture", "", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	now := time.Now().UTC()
	var seq int64
	add := func(asset storage.Asset, svc *storage.Service, evidence map[string]any) {
		seq++
		fact := sqlstore.Fact{
			Asset:   asset,
			Service: svc,
			Observation: storage.Observation{
				ID:           seq,
				SourceID:     src,
				SourceCursor: fmt.Sprintf("mastery-%d", seq),
				PayloadHash:  fmt.Sprintf("mastery-hash-%d", seq),
				Provenance:   storage.ProvenanceFixture,
				ObservedAt:   now,
				Evidence:     evidence,
			},
		}
		if _, err := store.IngestFacts(context.Background(), []sqlstore.Fact{fact}); err != nil {
			t.Fatalf("ingest %d: %v", seq, err)
		}
	}
	ip := func(v string) *string { return &v }
	svc := func(port int, proto, product string) *storage.Service {
		return &storage.Service{Port: port, Transport: "tcp", Protocol: proto, Name: proto, Product: product}
	}

	a7 := storage.Asset{Kind: storage.AssetKindIP, Value: "198.51.100.7", IP: ip("198.51.100.7"),
		ASN: 64500, ASNOrg: "Bench Telecom", GeoCountry: "US"}
	a8 := storage.Asset{Kind: storage.AssetKindIP, Value: "198.51.100.8", IP: ip("198.51.100.8"),
		ASN: 64501, ASNOrg: "Bench Cloud", GeoCountry: "DE"}
	add(a7, svc(443, "https", "nginx"), nil)
	add(a7, svc(80, "http", "apache"), map[string]any{"http": map[string]any{"status": 200, "title": "Mastery Demo"}})
	add(a7, svc(22, "ssh", "openssh"), map[string]any{"fingerprint": map[string]any{"technologies": []any{"openssh"}}})
	add(a8, svc(443, "https", "nginx-core"), nil)

	host1, host2, dom := "web1.bench.example", "mail.bench.example", "bench.example"
	add(storage.Asset{Kind: storage.AssetKindHostname, Value: host1, Hostname: &host1, Domain: &dom}, nil, nil)
	add(storage.Asset{Kind: storage.AssetKindHostname, Value: host2, Hostname: &host2, Domain: &dom}, nil, nil)
	add(storage.Asset{Kind: storage.AssetKindDomain, Value: dom, Domain: &dom}, nil, nil)
	return res.DB, New(res.DB)
}

// masteryValues extracts the (kind, value[, port]) keys of a result.
func masteryValues(res *search.Result, withPort bool) []string {
	var out []string
	for _, r := range res.Rows {
		k := r.AssetKind + "\x00" + r.AssetValue
		if withPort && r.Port != nil {
			k += fmt.Sprintf("\x00%d", *r.Port)
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustRows(t *testing.T, svc *Service, gql, mode string, limit int) *search.Result {
	t.Helper()
	res, err := svc.Search(context.Background(), search.Query{GQL: gql, Mode: mode, Limit: limit})
	if err != nil {
		t.Fatalf("query %q (%s): %v", gql, mode, err)
	}
	return res
}

func TestMasteryFieldCoverage(t *testing.T) {
	db, svc := seedMasteryCorpus(t)
	_ = db

	// Exact IP.
	if got := masteryValues(mustRows(t, svc, `ip=="198.51.100.7"`, "asset", 50), false); len(got) != 1 || got[0] != "ip\x00198.51.100.7" {
		t.Fatalf("ip==: %q", got)
	}
	// CIDR containment.
	if got := masteryValues(mustRows(t, svc, `ip IN_CIDR "198.51.100.0/24"`, "asset", 50), false); len(got) != 2 {
		t.Fatalf("IN_CIDR: %q", got)
	}
	// Port + service family.
	if got := masteryValues(mustRows(t, svc, `port==443`, "service", 50), true); len(got) != 2 {
		t.Fatalf("port==443: %q", got)
	}
	// ASN and country (typed columns with evidence).
	if got := masteryValues(mustRows(t, svc, `asn==64501`, "asset", 50), false); len(got) != 1 || got[0] != "ip\x00198.51.100.8" {
		t.Fatalf("asn==: %q", got)
	}
	if got := masteryValues(mustRows(t, svc, `country=="US"`, "asset", 50), false); len(got) != 1 {
		t.Fatalf("country==: %q", got)
	}
	// Technology from the fingerprint evidence.
	if got := masteryValues(mustRows(t, svc, `tech contains "openssh"`, "service", 50), true); len(got) != 1 {
		t.Fatalf("tech contains: %q", got)
	}
}

func TestMasteryOperatorCombinations(t *testing.T) {
	_, svc := seedMasteryCorpus(t)

	if got := masteryValues(mustRows(t, svc, `port==443 && app=="nginx"`, "service", 50), true); len(got) != 1 || got[0] != "ip\x00198.51.100.7\x00443" {
		t.Fatalf("AND combination: %q", got)
	}
	if got := masteryValues(mustRows(t, svc, `port==80 && app!="nginx"`, "service", 50), true); len(got) != 1 || got[0] != "ip\x00198.51.100.7\x0080" {
		t.Fatalf("negation: %q", got)
	}
	if got := masteryValues(mustRows(t, svc, `port IN (22, 80) && tech contains "openssh"`, "service", 50), true); len(got) != 1 || got[0] != "ip\x00198.51.100.7\x0022" {
		t.Fatalf("IN + tech: %q", got)
	}
	if got := masteryValues(mustRows(t, svc, `asn==64500 || asn==64501`, "asset", 50), false); len(got) != 2 {
		t.Fatalf("OR over typed columns: %q", got)
	}
}

func TestMasteryExactPrefixRelevanceOrder(t *testing.T) {
	_, svc := seedMasteryCorpus(t)

	// Prefix family: hostname *="web*" matches web1 but not mail.
	if got := masteryValues(mustRows(t, svc, `hostname *="web*"`, "asset", 50), false); len(got) != 1 || got[0] != "hostname\x00web1.bench.example" {
		t.Fatalf("hostname prefix: %q", got)
	}

	// Relevance (R114): substring-family queries rank the EXACT product
	// first — "nginx" before "nginx-core" — not merely "any order".
	res := mustRows(t, svc, `app contains "nginx"`, "service", 50)
	if len(res.Rows) != 2 {
		t.Fatalf("relevance rows = %d, want 2", len(res.Rows))
	}
	if *res.Rows[0].Product != "nginx" {
		t.Fatalf("relevance first product = %q, want exact match %q first", *res.Rows[0].Product, "nginx")
	}
	if *res.Rows[1].Product != "nginx-core" {
		t.Fatalf("relevance second product = %q", *res.Rows[1].Product)
	}
}

func TestMasteryCrossEntityDomainJoin(t *testing.T) {
	_, svc := seedMasteryCorpus(t)

	// One domain row must join to BOTH its hostnames (asset mode):
	// the cross-entity view the "asset" mode exists for.
	got := masteryValues(mustRows(t, svc, `domain=="bench.example"`, "asset", 50), false)
	want := []string{
		"domain\x00bench.example",
		"hostname\x00mail.bench.example",
		"hostname\x00web1.bench.example",
	}
	if len(got) != len(want) {
		t.Fatalf("domain join rows = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("domain join row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMasteryPaginationSortLimit(t *testing.T) {
	_, svc := seedMasteryCorpus(t)

	// Limit=1 with cursor walk: every row exactly once (no dup, no miss).
	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		res, err := svc.Search(context.Background(), search.Query{GQL: `ip IN_CIDR "198.51.100.0/24"`, Mode: "asset", Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("paged search: %v", err)
		}
		pages++
		for _, r := range res.Rows {
			key := r.AssetKind + "\x00" + r.AssetValue
			if seen[key] {
				t.Fatalf("pagination returned a duplicate row: %s", key)
			}
			seen[key] = true
		}
		if !res.HasMore || res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 2 {
		t.Fatalf("pagination collected %d rows, want 2", len(seen))
	}

	// Sorting: port:asc puts 80 before 443.
	res := mustRows(t, svc, `port IN (80, 443)`, "service", 50)
	if len(res.Rows) < 2 {
		t.Fatalf("sort rows = %d", len(res.Rows))
	}
	sorted, err := svc.Search(context.Background(), search.Query{GQL: `port IN (80, 443)`, Mode: "service", Limit: 50, Sort: "port:asc"})
	if err != nil {
		t.Fatalf("sort search: %v", err)
	}
	if *sorted.Rows[0].Port != 80 {
		t.Fatalf("port:asc first = %d, want 80", *sorted.Rows[0].Port)
	}
	if *sorted.Rows[len(sorted.Rows)-1].Port != 443 {
		t.Fatalf("port:asc last = %d, want 443", *sorted.Rows[len(sorted.Rows)-1].Port)
	}
	_ = res

	// Limit is honored.
	limited := mustRows(t, svc, `ip IN_CIDR "198.51.100.0/24"`, "asset", 1)
	if len(limited.Rows) != 1 || !limited.HasMore {
		t.Fatalf("limit=1: rows=%d has_more=%v", len(limited.Rows), limited.HasMore)
	}
}
