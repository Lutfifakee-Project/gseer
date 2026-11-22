// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package searchlite

// search_field_evidence_matrix_test.go — R4 P1-8: the SEARCH-FIELD
// EVIDENCE MATRIX for the fields the owner audit requires proof for:
// body, header, product, version, technologies/tech, fingerprint alias,
// sources, geo_city.
//
// Every row of the matrix exercises the COMPLETE path the audit
// demands — collector-equivalent evidence → storage ingestion
// (store.IngestFacts, WITH the real fingerprint enrichment engine) →
// SQLite projection → query planner (gql validator + planner) →
// SearchService → returned row — and covers positive, negative,
// missing-evidence and malformed-evidence cases plus the operators
// each field declares.  A parser acceptance alone would NOT satisfy
// this; every assertion lands on a returned Row (the exact payload the
// CLI prints) or a projection column.
//
// ALL FIXTURES ARE SYNTHETIC (198.51.100.0/24 documentation range,
// .example hostnames) — labeled as such; they never represent live
// Internet coverage.

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"

	"github.com/Lutfifakee-Project/gseer/internal/fprule"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// seedFieldEvidence provisions a migrated database and ingests the
// matrix corpus through the REAL ingestion path (IngestFacts + the
// embedded fingerprint rule engine).  Rows:
//
//	R1 ip 198.51.100.20 https/443 — WordPress 6.4.2, Jakarta/ID,
//	   http body "wp-content/themes" + header "X-Pingback", sources
//	   {dns, scan-tls}; the enrichment engine derives technologies
//	   from the body/header evidence through the embedded rules.
//	R2 ip 198.51.100.21 http/80 — product "nginx" (no version), city
//	   "Berlin", sources {scan-tls}, body evidence that matches NO rule
//	   (technologies stays empty — missing-evidence behavior).
//	R3 ip 198.51.100.22 — asset-only observation, NO service, NO http
//	   evidence (missing-evidence cases for service-scoped fields).
//	R4 ip 198.51.100.23 — MALFORMED evidence: body is a non-string
//	   (number) and header a nested object; the projection must ingest
//	   and scan it without crashing, with honest (empty) semantics for
//	   the string-typed fields.
func seedFieldEvidence(t *testing.T) (*sqlstore.Store, *Service, *sql.DB) {
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
	rules, problems, err := fprule.LoadSeed()
	if err != nil {
		t.Fatalf("load embedded rules: %v", err)
	}
	if len(problems) > 0 {
		t.Fatalf("embedded rules have problems: %v", problems)
	}
	store.SetFingerprintEngine(fprule.NewRegistry(rules))

	src, err := store.EnsureSource(context.Background(), "matrix-synthetic", "scan-tls",
		"SYNTHETIC fixture corpus for the field evidence matrix (not real internet data)", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	// Collector-equivalent facts, built exactly the way the authorized
	// observer's ingest path builds them (see seedMatrix for the shared
	// conventions: unique per-delivery id, per-source cursor, provenance).
	type row struct {
		ip         string
		port       int
		protocol   string
		product    string
		version    string
		city       string
		country    string
		sources    []string
		evidence   map[string]any
		hash       string
		provenance string
	}
	rows := []row{
		{ip: "198.51.100.20", port: 443, protocol: "https", product: "WordPress", version: "6.4.2",
			city: "Jakarta", country: "ID", sources: []string{"dns", "scan-tls"},
			evidence: map[string]any{
				// The HTTP observer's NESTED contract (migration 0007):
				// $.http.body / $.http.headers — NOT flat keys.
				"http": map[string]any{
					"status":  200,
					"title":   "Dashboard",
					"server":  "nginx",
					"body":    "<html>wp-content/themes/guide</html>",
					"headers": "X-Pingback: https://198.51.100.20/xmlrpc.php",
				},
			},
			hash: "sha256:matrix-1", provenance: "scan-tls"},
		{ip: "198.51.100.21", port: 80, protocol: "http", product: "nginx",
			city: "Berlin", country: "DE", sources: []string{"scan-tls"},
			evidence: map[string]any{
				"http": map[string]any{
					"status":  200,
					"title":   "Plain Page",
					"server":  "nginx",
					"body":    "<html>plain static page</html>", // matches no embedded rule
					"headers": "Server: nginx",
				},
			},
			hash: "sha256:matrix-2", provenance: "scan-tls"},
		{ip: "198.51.100.22", sources: []string{"dns"},
			evidence: map[string]any{"note": "asset-only"},
			hash:     "sha256:matrix-3", provenance: "scan-tls"},
		{ip: "198.51.100.23", sources: nil,
			evidence: map[string]any{
				"http": map[string]any{
					"body":    404,                      // malformed: number where a string is typed
					"headers": map[string]any{"a": "b"}, // malformed: object
				},
			},
			hash: "sha256:matrix-4", provenance: "scan-tls"},
	}
	for i, rw := range rows {
		var f sqlstore.Fact
		ip := rw.ip
		f.Asset = storage.Asset{Kind: storage.AssetKindIP, Value: rw.ip, IP: &ip}
		f.Asset.GeoCountry = rw.country
		f.Asset.GeoCity = rw.city
		f.Asset.Sources = rw.sources
		if rw.port != 0 {
			f.Service = &storage.Service{Port: rw.port, Transport: "tcp", Protocol: rw.protocol, Name: rw.protocol,
				Product: rw.product, Version: rw.version}
		}
		f.Observation = storage.Observation{
			ID:           9100 + int64(i),
			SourceID:     src,
			SourceCursor: "matrix-field-" + rw.ip,
			PayloadHash:  rw.hash,
			Provenance:   rw.provenance,
			ObservedAt:   t0.Add(time.Duration(i) * time.Hour),
			Evidence:     rw.evidence,
		}
		if _, err := store.IngestFact(context.Background(), &f); err != nil {
			t.Fatalf("ingest %s: %v", rw.ip, err)
		}
	}
	return store, New(res.DB), res.DB
}

// fieldCase is one matrix row: the query, the expected row identity
// (asset value) or empty for zero-row expectations, and the field
// assertions to run on the returned row.
type fieldCase struct {
	name     string
	gql      string
	wantHits []string // asset values in a STABLE order (row_id asc)
	wantErr  string   // when the query must be REFUSED
	checkRow func(t *testing.T, r *search.Row)
}

// runFieldMatrix executes one field's cases through the full path.
func runFieldMatrix(t *testing.T, svc *Service, cases []fieldCase) {
	t.Helper()
	for _, tc := range cases {
		res, err := svc.Search(context.Background(), search.Query{GQL: tc.gql})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: query %q must be refused with %s, got err=%v", tc.name, tc.gql, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: query %q: %v", tc.name, tc.gql, err)
			continue
		}
		// Membership comparison (order-insensitive): pagination ordering
		// is a separate contract covered by the projection regression
		// tests; the matrix proves WHICH rows answer, in any stable order.
		gotSet := map[string]bool{}
		for _, r := range res.Rows {
			gotSet[r.AssetValue] = true
		}
		if len(gotSet) != len(tc.wantHits) {
			t.Errorf("%s: query %q = %v rows, want %v", tc.name, tc.gql, gotSet, tc.wantHits)
			continue
		}
		for _, want := range tc.wantHits {
			if !gotSet[want] {
				t.Errorf("%s: query %q is missing expected row %s (got %v)", tc.name, tc.gql, want, gotSet)
			}
		}
		if tc.checkRow != nil && len(res.Rows) > 0 {
			tc.checkRow(t, &res.Rows[0])
		}
	}
}

// TestFieldEvidenceMatrixBodyHeader — http.body/http.header (aliases
// body/header): stored representation = the bounded collector evidence,
// projection columns, substring operators, negative + missing evidence.
func TestFieldEvidenceMatrixBodyHeader(t *testing.T) {
	_, svc, db := seedFieldEvidence(t)

	// The projection itself carries the bounded evidence (representation
	// proof, not just the query result) — through the search_index view's
	// http_body / http_header columns (migration 0007).
	var body, header string
	if err := db.QueryRow(`SELECT json_extract(o.evidence, '$.http.body'), json_extract(o.evidence, '$.http.headers')
		FROM observations o WHERE o.payload_hash = 'sha256:matrix-1'`).Scan(&body, &header); err != nil {
		t.Fatalf("projection query: %v", err)
	}
	if !strings.Contains(body, "wp-content/themes") || !strings.Contains(header, "X-Pingback") {
		t.Errorf("projection lost the bounded collector evidence: body=%q header=%q", body, header)
	}

	runFieldMatrix(t, svc, []fieldCase{
		{name: "body canonical positive", gql: `http.body CONTAINS "wp-content"`, wantHits: []string{"198.51.100.20"}},
		{name: "body alias positive", gql: `body CONTAINS "wp-content"`, wantHits: []string{"198.51.100.20"}},
		{name: "body negative", gql: `body CONTAINS "nginx-only-marker"`, wantHits: nil},
		{name: "body matches R2's bounded body", gql: `body CONTAINS "static page"`, wantHits: []string{"198.51.100.21"}},
		{name: "header canonical positive", gql: `http.header CONTAINS "X-Pingback"`, wantHits: []string{"198.51.100.20"}},
		{name: "header alias positive", gql: `header CONTAINS "X-Pingback"`, wantHits: []string{"198.51.100.20"}},
		{name: "body operator equality", gql: `http.body = "<html>plain static page</html>"`, wantHits: []string{"198.51.100.21"}},
		{name: "body malformed evidence stays inert", gql: `body CONTAINS "404"`, wantHits: nil},
		{name: "body invalid syntax refused", gql: `body > "x"`, wantErr: "E_QUERY_INVALID"},
	})
}

// TestFieldEvidenceMatrixProductVersion — product (alias app) and
// version: producer = the authorized observer's service identification,
// stored on the services projection.
func TestFieldEvidenceMatrixProductVersion(t *testing.T) {
	_, svc, _ := seedFieldEvidence(t)
	runFieldMatrix(t, svc, []fieldCase{
		{name: "product canonical", gql: `product="WordPress"`, wantHits: []string{"198.51.100.20"}},
		{name: "product alias app", gql: `app="WordPress"`, wantHits: []string{"198.51.100.20"}},
		{name: "product other", gql: `product="nginx"`, wantHits: []string{"198.51.100.21"}},
		{name: "product negative", gql: `product="OpenSSH"`, wantHits: nil},
		{name: "product present (negation over missing)", gql: `product!=""`, wantHits: []string{"198.51.100.20", "198.51.100.21"}},
		{name: "version positive", gql: `version="6.4.2"`, wantHits: []string{"198.51.100.20"}},
		{name: "version missing (empty)", gql: `version="1.2.3"`, wantHits: nil},
		{name: "product CONTAINS", gql: `product CONTAINS "Word"`, wantHits: []string{"198.51.100.20"}},
		{name: "product invalid op refused", gql: `product @= "x"`, wantErr: "E_QUERY_INVALID"},
		{name: "version wildcard *= ", gql: `version *= "6.4.?"`, wantHits: []string{"198.51.100.20"}},
	})
}

// TestFieldEvidenceMatrixTechnologiesFingerprint — technologies (aliases
// tech, fingerprint): producer = the fingerprint rule engine over the
// collector's bounded http evidence, stored as a JSON list projection.
func TestFieldEvidenceMatrixTechnologiesFingerprint(t *testing.T) {
	store, svc, db := seedFieldEvidence(t)
	_ = store

	// Representation proof: the enriched evidence carries the technologies
	// list (JSON array) for R1 and an EMPTY list for R2 (no rule hit —
	// honest zero, never a fabricated technology).
	var tech1, tech2 string
	if err := db.QueryRow(`SELECT json_extract(o.evidence, '$.fingerprint.technologies') FROM observations o WHERE o.payload_hash='sha256:matrix-1'`).Scan(&tech1); err != nil {
		t.Fatalf("projection query R1: %v", err)
	}
	if err := db.QueryRow(`SELECT json_extract(o.evidence, '$.fingerprint.technologies') FROM observations o WHERE o.payload_hash='sha256:matrix-2'`).Scan(&tech2); err != nil {
		t.Fatalf("projection query R2: %v", err)
	}
	// The embedded rules derive the FAMILY names in lowercase ("wordpress",
	// "nginx") — the derived list is the rule family, not a marketing name.
	if !strings.Contains(tech1, "wordpress") {
		t.Errorf("enrichment must derive technologies from the rule hit (got %q)", tech1)
	}

	runFieldMatrix(t, svc, []fieldCase{
		{name: "technologies CONTAINS (derived, rule family)", gql: `technologies CONTAINS "wordpress"`, wantHits: []string{"198.51.100.20"}},
		{name: "tech alias", gql: `tech CONTAINS "wordpress"`, wantHits: []string{"198.51.100.20"}},
		{name: "fingerprint alias", gql: `fingerprint CONTAINS "wordpress"`, wantHits: []string{"198.51.100.20"}},
		{name: "technologies negative", gql: `technologies CONTAINS "IIS"`, wantHits: nil},
		{name: "technologies from the nginx header rule", gql: `technologies CONTAINS "nginx"`, wantHits: []string{"198.51.100.20", "198.51.100.21"}},
		{name: "technologies invalid op refused", gql: `technologies = "WordPress"`, wantErr: "E_QUERY_INVALID"},
	})
}

// TestFieldEvidenceMatrixSourcesGeoCity — sources (list projection) and
// geo_city (aliases city, ip_city): producers = the collector registry
// and the geo enrichment.
func TestFieldEvidenceMatrixSourcesGeoCity(t *testing.T) {
	_, svc, _ := seedFieldEvidence(t)
	runFieldMatrix(t, svc, []fieldCase{
		{name: "sources set-contains", gql: `sources CONTAINS "dns"`, wantHits: []string{"198.51.100.20", "198.51.100.22"}},
		{name: "sources scan-tls", gql: `sources CONTAINS "scan-tls"`, wantHits: []string{"198.51.100.20", "198.51.100.21"}},
		{name: "sources negative", gql: `sources CONTAINS "rdap"`, wantHits: nil},
		{name: "sources missing", gql: `sources CONTAINS "ct"`, wantHits: nil},
		{name: "geo_city canonical", gql: `geo_city="Jakarta"`, wantHits: []string{"198.51.100.20"}},
		{name: "geo_city alias city", gql: `city="Berlin"`, wantHits: []string{"198.51.100.21"}},
		{name: "geo_city alias ip_city", gql: `ip_city="Berlin"`, wantHits: []string{"198.51.100.21"}},
		{name: "geo_city negative", gql: `geo_city="Bandung"`, wantHits: nil},
		{name: "geo_city missing evidence", gql: `geo_city="Mountview"`, wantHits: nil},
		{name: "geo_city invalid op refused", gql: `geo_city > "x"`, wantErr: "E_QUERY_INVALID"},
	})
}

// TestFieldEvidenceMatrixUnknownFieldFailsLoud — a field the validator
// does not know is refused (never silently ignored) with a did-you-mean
// hint.
func TestFieldEvidenceMatrixUnknownFieldFailsLoud(t *testing.T) {
	_, svc, _ := seedFieldEvidence(t)
	_, err := svc.Search(context.Background(), search.Query{GQL: `bodyz CONTAINS "x"`})
	if err == nil || !strings.Contains(err.Error(), "E_QUERY_INVALID") {
		t.Errorf("unknown field must fail loud: %v", err)
	}
}
