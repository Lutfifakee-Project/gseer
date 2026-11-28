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

package searchlite_test

// relevance_integration_test.go — R114: substring-family relevance
// ordering (exact > prefix > rest) through the production search
// service, including the pagination contract (the cursor carries the
// tier, and page 2 continues without skipping or repeating rows).

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// seedRelevance ingests a product corpus where the CONTAINS "nginx"
// matched set spans all three relevance tiers: exact ("nginx"),
// prefix ("nginx-proxy"), substring ("openresty-nginx").
func seedRelevance(t *testing.T) *searchlite.Service {
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
	src, err := store.EnsureSource(context.Background(), "relevance-fixture", "relevance-fixture", "", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}

	mk := func(ip string, port int, product string) sqlstore.Fact {
		v := ip
		obsID := obsSeq.next()
		f := sqlstore.Fact{
			Asset: storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &v},
			Observation: storage.Observation{
				ID:           obsID,
				SourceID:     src,
				SourceCursor: fmt.Sprintf("rel-%s-%d", ip, port),
				PayloadHash:  fmt.Sprintf("rel-hash-%s-%d", ip, port),
				Provenance:   storage.ProvenanceFixture,
				ObservedAt:   time.Now().UTC(),
			},
		}
		if port != 0 {
			f.Service = &storage.Service{
				Port:      port,
				Transport: "tcp",
				Protocol:  "http",
				Name:      "http",
				Product:   product,
			}
		}
		return f
	}

	facts := []sqlstore.Fact{
		mk("198.51.100.11", 80, "nginx-proxy"),     // tier 1 (prefix)
		mk("198.51.100.12", 80, "openresty-nginx"), // tier 2 (substring)
		mk("198.51.100.10", 80, "nginx"),           // tier 0 (exact)
		mk("198.51.100.13", 80, "nginx"),           // tier 0 (exact, second row)
		mk("198.51.100.14", 80, "apache"),          // outside the matched set
	}
	if _, err := store.IngestFacts(context.Background(), facts); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return searchlite.New(res.DB)
}

// TestRelevanceOrdering — the default ordering for an eligible query
// ranks exact matches before prefix matches before substring matches.
// The matched SET is unchanged (no apache row).
func TestRelevanceOrdering(t *testing.T) {
	svc := seedRelevance(t)
	res, err := svc.Search(context.Background(), search.Query{
		GQL: `product CONTAINS "nginx"`,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Rows) != 4 {
		t.Fatalf("matched set = %d rows, want 4 (no relevance-free row may leak in): %+v", len(res.Rows), res.Rows)
	}
	wantOrder := []string{"nginx", "nginx", "nginx-proxy", "openresty-nginx"}
	for i, w := range wantOrder {
		if res.Rows[i].Product == nil || *res.Rows[i].Product != w {
			t.Fatalf("row %d product = %v, want %q (tiers: exact > prefix > substring)", i, res.Rows[i].Product, w)
		}
	}
}

// TestRelevancePagination — page 2 via the cursor continues the tier
// order without repeating or skipping rows (the cursor carries the
// tier, and the cursor predicate compares the same CASE the ORDER BY
// used).
func TestRelevancePagination(t *testing.T) {
	svc := seedRelevance(t)
	page1, err := svc.Search(context.Background(), search.Query{
		GQL:   `product CONTAINS "nginx"`,
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if page1.NextCursor == "" {
		t.Fatal("page1 returned no cursor — pagination contract broken")
	}
	seen := map[string]bool{}
	for _, r := range page1.Rows {
		if r.Product == nil {
			t.Fatal("nil product on page 1")
		}
		seen[*r.Product] = true
	}
	page2, err := svc.Search(context.Background(), search.Query{
		GQL:    `product CONTAINS "nginx"`,
		Limit:  10,
		Cursor: page1.NextCursor,
	})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	total := len(page1.Rows) + len(page2.Rows)
	if total != 4 {
		t.Fatalf("pages returned %d rows total, want 4 (no skips/repeats)", total)
	}
	for _, r := range page2.Rows {
		if r.Product == nil {
			t.Fatal("nil product on page 2")
		}
		if seen[*r.Product] {
			t.Fatalf("product %q repeated across the cursor boundary", *r.Product)
		}
		seen[*r.Product] = true
	}
	if seen["apache"] {
		t.Fatal("apache leaked into the relevance-paginated matched set")
	}
}

// TestRelevanceExplicitSortRequiresTextMatch — `--sort relevance:asc`
// on a query without a substring-family predicate is a clear error,
// not a silent rank over nothing.
func TestRelevanceExplicitSortRequiresTextMatch(t *testing.T) {
	svc := seedRelevance(t)
	_, err := svc.Search(context.Background(), search.Query{
		GQL:  `ip == "198.51.100.10"`,
		Sort: "relevance:asc",
	})
	if err == nil {
		t.Fatal("relevance sort without a text-match query must fail")
	}
	var qe *search.QueryError
	if !errors.As(err, &qe) || qe.Code != "E_QUERY_INVALID" {
		t.Fatalf("want E_QUERY_INVALID (wrapGQLError), got %v", err)
	}
}

// TestRelevanceNotEligibleKeepsDefault — OR/NOT/free-text/multi-text
// queries are NOT eligible: they keep the plain last_seen default (no
// rank, no panic).
func TestRelevanceNotEligibleKeepsDefault(t *testing.T) {
	svc := seedRelevance(t)
	for _, q := range []string{
		`product CONTAINS "nginx" || product CONTAINS "apache"`,
		`product CONTAINS "nginx" && port == 80`,
	} {
		res, err := svc.Search(context.Background(), search.Query{GQL: q})
		if err != nil {
			t.Fatalf("Search(%q): %v", q, err)
		}
		if len(res.Rows) == 0 {
			t.Fatalf("query %q returned no rows", q)
		}
	}
}
