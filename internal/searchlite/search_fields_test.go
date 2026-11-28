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

// search_fields_test.go — R37 search-field expansion: the new
// searchable intelligence surfaces (ip2asn prefix, service banner, TLS
// issuer organization, per-name HTTP headers) end-to-end through a
// fresh personal store, migration 0007's view, the planner and the
// validator.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// seedScanEvidence ingests one IP asset with a TLS observation (issuer
// org), an HTTP observation (captured headers), an SSH fingerprint
// observation (banner) and an IP-to-ASN attribution observation
// (prefix) — the R37 evidence shapes — into a fresh store.
func seedScanEvidence(t *testing.T) (*sql.DB, *Service) {
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
	src, err := store.EnsureSource(context.Background(), "scan-evidence", "fixture", "", nil)
	if err != nil {
		t.Fatalf("scan source: %v", err)
	}
	now := time.Now().UTC()
	mkObs := func(id int64, evidence map[string]any, service *storage.Service) sqlstore.Fact {
		v := "198.51.100.7"
		return sqlstore.Fact{
			Asset:   storage.Asset{Kind: storage.AssetKindIP, Value: v, IP: &v},
			Service: service,
			Observation: storage.Observation{
				ID:           id,
				SourceID:     src,
				SourceCursor: fmt.Sprintf("scan-obs-%d", id),
				PayloadHash:  "scan-hash",
				Provenance:   storage.ProvenanceFixture,
				ObservedAt:   now,
				Evidence:     evidence,
			},
		}
	}
	facts := []sqlstore.Fact{
		mkObs(1, map[string]any{"tls": map[string]any{
			"version": "TLS 1.3", "cert_subject_cn": "demo.example",
			"cert_issuer_cn": "Demo CA", "cert_issuer_org": "SSL Corporation",
		}}, &storage.Service{Port: 443, Transport: "tcp", Protocol: "https", Name: "https"}),
		mkObs(2, map[string]any{"http": map[string]any{
			"status": 200, "title": "R37 Demo", "server": "nginx",
			"headers": map[string]any{"x-powered-by": "Next.js", "server": "nginx", "alt-svc": `h3=":443"`},
		}}, &storage.Service{Port: 80, Transport: "tcp", Protocol: "http", Name: "http"}),
		mkObs(3, map[string]any{"fingerprint": map[string]any{"technologies": []any{"openssh"}},
			"ssh": map[string]any{"banner": "SSH-2.0-OpenSSH_9.6"}},
			&storage.Service{Port: 22, Transport: "tcp", Protocol: "ssh", Name: "ssh"}),
		mkObs(4, map[string]any{"ip2asn": map[string]any{
			"asn": 64500, "prefix": "198.51.100.0/24", "country": "US", "raw": "64500 | 198.51.100.0/24 | US | arin |",
		}}, nil),
	}
	if _, err := store.IngestFacts(context.Background(), facts); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return res.DB, New(res.DB)
}

func runFieldSearch(t *testing.T, svc *Service, q string, opts func(*search.Query)) *search.Result {
	t.Helper()
	req := search.Query{GQL: q, WithStats: false}
	if opts != nil {
		opts(&req)
	}
	res, err := svc.Search(context.Background(), req)
	if err != nil {
		t.Fatalf("Search(%q): %v", q, err)
	}
	return res
}

func TestHTTPHeaderDynamicField(t *testing.T) {
	_, svc := seedScanEvidence(t)
	if res := runFieldSearch(t, svc, `http.header.x-powered-by == "Next.js"`, nil); len(res.Rows) != 1 {
		t.Fatalf("dynamic header eq: rows = %d, want 1\n", len(res.Rows))
	}
	// The fprule-consistent alias form resolves to the same field.
	if res := runFieldSearch(t, svc, `http.headers.alt-svc CONTAINS "h3"`, nil); len(res.Rows) != 1 {
		t.Fatalf("dynamic header contains (alias form): rows = %d, want 1", len(res.Rows))
	}
	if res := runFieldSearch(t, svc, `http.header.x-powered-by == "nginx"`, nil); len(res.Rows) != 0 {
		t.Fatalf("dynamic header wrong value: rows = %d, want 0", len(res.Rows))
	}
	if res := runFieldSearch(t, svc, `http.headers CONTAINS "nginx"`, nil); len(res.Rows) != 1 {
		t.Fatalf("raw headers CONTAINS: rows = %d, want 1 (headers are per-service: only the :80 row captured them)", len(res.Rows))
	}
}

func TestPrefixField(t *testing.T) {
	_, svc := seedScanEvidence(t)
	if res := runFieldSearch(t, svc, `prefix == "198.51.100.0/24"`, nil); len(res.Rows) < 1 {
		t.Fatalf("prefix eq: rows = %d, want >= 1", len(res.Rows))
	}
	if res := runFieldSearch(t, svc, `prefix *= "198.51.100.*"`, nil); len(res.Rows) < 1 {
		t.Fatalf("prefix wildcard: rows = %d, want >= 1", len(res.Rows))
	}
	if res := runFieldSearch(t, svc, `prefix == "203.0.113.0/24"`, nil); len(res.Rows) != 0 {
		t.Fatalf("prefix other: rows = %d, want 0", len(res.Rows))
	}
}

func TestBannerAndIssuerOrgFields(t *testing.T) {
	_, svc := seedScanEvidence(t)
	if res := runFieldSearch(t, svc, `banner *= "*OpenSSH*"`, nil); len(res.Rows) != 1 {
		t.Fatalf("banner wildcard: rows = %d, want 1", len(res.Rows))
	}
	if res := runFieldSearch(t, svc, `tls.cert_issuer_org CONTAINS "SSL Corporation"`, nil); len(res.Rows) != 1 {
		t.Fatalf("issuer org contains: rows = %d, want 1", len(res.Rows))
	}
}

func TestDynamicHeaderProjectionRejected(t *testing.T) {
	_, svc := seedScanEvidence(t)
	_, err := svc.Search(context.Background(), search.Query{
		GQL: `http.header.server == "nginx"`, Fields: []string{"http.header.server"},
	})
	if err == nil {
		t.Fatalf("dynamic header projection: want a filter-only error, got nil")
	}
}

func TestDynamicHeaderValidatorCharset(t *testing.T) {
	_, svc := seedScanEvidence(t)
	for _, bad := range []string{`http.header."quoted" == "x"`, `http.header.a b == "x"`} {
		if _, err := svc.Search(context.Background(), search.Query{GQL: bad}); err == nil {
			t.Fatalf("invalid dynamic header %q: want a validation error, got nil", bad)
		}
	}
}
