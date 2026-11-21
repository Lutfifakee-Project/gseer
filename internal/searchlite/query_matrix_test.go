// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package searchlite_test

// query_matrix_test.go — the v0.3.2 query-engine regression matrix for
// the personal (SQLite) engine, over a DETERMINISTIC hand-ingested
// corpus (TEST-NET / example.* documentation values only — no internet
// discovery data, no network).  Every operator, every registry field,
// the compat aliases, the value-coercion rules, and the two v0.3.2
// fixes get a positive AND a negative assertion:
//
//   - stale=="false" must MATCH rows (the TEXT "false" param never
//     equaled the INTEGER 0/1 SQLite column — the owner evidence hit);
//   - observed_at must carry the REAL evidence time, not the ingest
//     stamp (migration 0006);
//   - cert.issuer / cert.subject / organization aliases;
//   - the CONTAINS LIKE-escape contract (% must not become a wildcard).

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

var matrixSeq int64

// seedMatrix ingests the deterministic matrix corpus:
//
//	1  ip 198.51.100.10  :443 https  "Admin Dashboard" / nginx  US  t0
//	2  ip 198.51.100.11  :80  http   "100% uptime"     / Apache DE  t0+1h
//	3  ip 198.51.100.12  :8080 http   "1000 uptime"     / Apache DE  t0+2h
//	4  www.example.net   :443 https   TLS Matrix CA (sans example.net)  t0+3h
//	5  example.net       asset-only domain                             t0+4h
//	6  ip 2001:db8::10   :443 https                                    t0+5h
//	7  ip 198.51.100.99  :443 https   US  t0-48h
func seedMatrix(t *testing.T) (*sqlstore.Store, *searchlite.Service) {
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
	src, err := store.EnsureSource(context.Background(), "fixture", "fixture", "", nil)
	if err != nil {
		t.Fatalf("fixture source: %v", err)
	}
	t0 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	type row struct {
		kind, value string
		port        int
		protocol    string
		title       string
		server      string
		country     string
		domain      string
		tls         map[string]any
		at          time.Time
	}
	rows := []row{
		{kind: "ip", value: "198.51.100.10", port: 443, protocol: "https",
			title: "Admin Dashboard", server: "nginx", country: "US", at: t0},
		{kind: "ip", value: "198.51.100.11", port: 80, protocol: "http",
			title: "100% uptime", server: "Apache", country: "DE", at: t0.Add(time.Hour)},
		{kind: "ip", value: "198.51.100.12", port: 8080, protocol: "http",
			title: "1000 uptime", server: "Apache", country: "DE", at: t0.Add(2 * time.Hour)},
		{kind: "hostname", value: "www.example.net", port: 443, protocol: "https",
			domain: "example.net", at: t0.Add(3 * time.Hour),
			tls: map[string]any{"version": "TLS 1.3", "cert_subject_cn": "www.example.net",
				"cert_issuer_cn": "Matrix CA", "cert_expiry": "2027-01-01T00:00:00Z",
				"cert_serial": "abcd1234", "cert_sans_dns": []string{"www.example.net", "example.net"}}},
		{kind: "domain", value: "example.net", at: t0.Add(4 * time.Hour)},
		{kind: "ip", value: "2001:db8::10", port: 443, protocol: "https", at: t0.Add(5 * time.Hour)},
		{kind: "ip", value: "198.51.100.99", port: 443, protocol: "https",
			country: "US", at: t0.Add(-48 * time.Hour)},
	}
	for i, rw := range rows {
		var f sqlstore.Fact
		switch rw.kind {
		case "ip":
			v := rw.value
			f.Asset = storage.Asset{Kind: storage.AssetKindIP, Value: rw.value, IP: &v}
		case "domain":
			v := rw.value
			f.Asset = storage.Asset{Kind: storage.AssetKindDomain, Value: rw.value, Domain: &v}
		default:
			v := rw.value
			d := rw.domain
			f.Asset = storage.Asset{Kind: storage.AssetKindHostname, Value: rw.value, Hostname: &v, Domain: &d}
		}
		f.Asset.GeoCountry = rw.country
		f.Asset.Sources = []string{"fixture"}
		if rw.value == "198.51.100.10" {
			f.Asset.ASN = 64512
			f.Asset.ASNOrg = "AS64512 MATRIX-VANNET"
		}
		f.Observation = storage.Observation{
			ID:           matrixSeq + 1,
			SourceID:     src,
			SourceCursor: fmt.Sprintf("matrix-%d", i),
			PayloadHash:  fmt.Sprintf("matrix-hash-%d", i),
			Provenance:   storage.ProvenanceFixture,
			ObservedAt:   rw.at,
		}
		if rw.port != 0 {
			f.Service = &storage.Service{Port: rw.port, Transport: "tcp", Protocol: rw.protocol, Name: rw.protocol}
			if rw.title != "" || rw.server != "" {
				f.Observation.Evidence = map[string]any{
					"http": map[string]any{"status": 200, "title": rw.title, "server": rw.server},
				}
			}
			if rw.tls != nil {
				f.Observation.Evidence = map[string]any{"tls": rw.tls}
			}
		}
		if _, err := store.IngestFact(context.Background(), &f); err != nil {
			t.Fatalf("ingest %s: %v", rw.value, err)
		}
		matrixSeq++
	}
	return store, searchlite.New(res.DB)
}

func ptrInt(n int) *int { return &n }

// count runs one query and returns the row count.
func count(t *testing.T, svc *searchlite.Service, gql string) int {
	t.Helper()
	res, err := svc.Search(context.Background(), search.Query{GQL: gql, Limit: 300})
	if err != nil {
		t.Fatalf("search %q: %v", gql, err)
	}
	return len(res.Rows)
}

// TestQueryOperatorMatrix — every operator with a positive and a
// negative case over the deterministic corpus (7 rows).
func TestQueryOperatorMatrix(t *testing.T) {
	_, svc := seedMatrix(t)
	cases := []struct {
		gql string
		n   int
	}{
		// equality family + quoted-int coercion (compat layer)
		{"port=443", 4}, {"port==443", 4}, {`port="443"`, 4}, {`port="4433"`, 0},
		{"port != 443", 2}, {`port != "443"`, 2},
		// ordering operators
		{"port >= 80 && port <= 443", 5}, {"port > 443", 1}, {"port < 443", 1},
		{"port <= 80", 1}, {"asn >= 64512", 1}, {"asn < 64512", 6},
		// boolean algebra, grouping, negation
		{`protocol="https" && port=443`, 4},
		{`port=80 || port=8080`, 2},
		{`!(protocol="https")`, 2},
		{`!(port=443 || port=80)`, 1},
		{`(port=80 || port=8080) && country="DE"`, 2},
		{`! (country="US")`, 5}, // missing geo is stored as '' (not NULL), so it negates to TRUE
		// IN lists (mixed bare/quoted integers)
		{"port IN (80, 8080)", 2}, {`port IN (80, "443")`, 5}, {`country IN ("US", "DE")`, 4},
		// CIDR (v4 and v6)
		{`ip IN_CIDR "198.51.100.0/24"`, 4}, {`ip IN_CIDR "2001:db8::/32"`, 1},
		{`ip IN_CIDR "203.0.113.0/24"`, 0},
		// wildcard match
		{`hostname *= "*.example.net"`, 1}, {`asset_value *= "198.51.100.*"`, 4},
		// CONTAINS + the LIKE-escape contract (% must stay literal)
		{`title CONTAINS "Dashboard"`, 1}, {`title CONTAINS "100% up"`, 1},
		{`server CONTAINS "apache"`, 2}, // case-insensitive
		// IN_DOMAIN (self + subdomains)
		{`domain IN_DOMAIN "example.net"`, 2},
		// presence tests
		{"exists(port)", 6}, {"exists(http.title)", 3}, {"exists(cert_expiry)", 1},
		{"exists(http.title) || exists(cert_expiry)", 4},
		// free text: quoted term and unquoted bare word (v0.3.2 grammar)
		{`"dashboard"`, 1}, {"dashboard", 1},
		// empty-value semantics
		{`http.title=""`, 4}, {`server!=""`, 3},
		// freshness surfaces
		{`last_seen > "2026-01-01T00:00:00Z"`, 7},
		{`after="2026-01-15"`, 7}, {`before="2030-01-01"`, 7},
		// derived compat fields
		{`is_domain="true"`, 2}, {`is_ipv6="true"`, 1}, {`cert.is_expired="false"`, 1},
		{`host="www.example.net"`, 1}, {`host="198.51.100.10"`, 1},
	}
	for _, tc := range cases {
		if got := count(t, svc, tc.gql); got != tc.n {
			t.Errorf("query %q = %d rows, want %d", tc.gql, got, tc.n)
		}
	}
}

// TestStaleBoolLiteralRegression — the v0.3.2 owner-evidence bug: the
// stale column stores INTEGER 0/1 on SQLite, and the planner used to
// bind the quoted literal as TEXT ("false"), which can never equal 0 —
// stale=="false" returned 0 rows over a fully fresh index.
func TestStaleBoolLiteralRegression(t *testing.T) {
	_, svc := seedMatrix(t)
	if got := count(t, svc, `stale=="false"`); got != 7 {
		t.Errorf(`stale=="false" = %d rows, want 7 (every row is fresh)`, got)
	}
	if got := count(t, svc, `stale=="true"`); got != 0 {
		t.Errorf(`stale=="true" = %d rows, want 0`, got)
	}
	if got := count(t, svc, `stale != "false"`); got != 0 {
		t.Errorf(`stale != "false" = %d rows, want 0`, got)
	}
	if got := count(t, svc, `stale != "true"`); got != 7 {
		t.Errorf(`stale != "true" = %d rows, want 7`, got)
	}
}

// TestObservedAtEvidenceTime — migration 0006 projects the REAL
// evidence time; it must differ from last_seen (the ingest stamp) and
// answer range filters exactly.
func TestObservedAtEvidenceTime(t *testing.T) {
	_, svc := seedMatrix(t)
	if got := count(t, svc, `observed_at > "2026-01-15T00:30:00Z"`); got != 5 {
		t.Errorf("observed_at > t0+30m = %d rows, want 5 (t0+1h..t0+5h)", got)
	}
	if got := count(t, svc, `observed_at < "2026-01-15T00:00:00Z"`); got != 1 {
		t.Errorf("observed_at < t0 = %d rows, want 1 (the t0-48h row)", got)
	}
	if got := count(t, svc, `observed_at >= "2026-01-15T00:00:00Z" && observed_at <= "2026-01-15T01:00:00Z"`); got != 2 {
		t.Errorf("observed_at window [t0, t0+1h] = %d rows, want 2", got)
	}
	// Every row carries an observation → observed_at present on all.
	if got := count(t, svc, `exists(observed_at)`); got != 7 {
		t.Errorf("exists(observed_at) = %d rows, want 7", got)
	}
	// last_seen is the ingest stamp (now), NOT the evidence time: the
	// two surfaces must be distinguishable.
	if got := count(t, svc, `last_seen > "2030-01-01T00:00:00Z"`); got != 0 {
		t.Errorf("last_seen > 2030 = %d rows, want 0 (ingest stamps are ~now, not 2030)", got)
	}
}

// TestCompatAliases — v0.3.2 registry aliases: cert.issuer,
// cert.subject, organization.
func TestCompatAliases(t *testing.T) {
	_, svc := seedMatrix(t)
	cases := []struct {
		gql string
		n   int
	}{
		{`cert.issuer="Matrix CA"`, 1},
		{`cert.issuer CONTAINS "Matrix"`, 1},
		{`cert.issuer CONTAINS "Nomatch"`, 0},
		{`cert.subject="www.example.net"`, 1},
		{`cert.domain CONTAINS "example."`, 1},
		{`organization CONTAINS "MATRIX"`, 1},
		{`organization="AS64512 MATRIX-VANNET"`, 1},
		{`organization CONTAINS "Nowhere"`, 0},
	}
	for _, tc := range cases {
		if got := count(t, svc, tc.gql); got != tc.n {
			t.Errorf("query %q = %d rows, want %d", tc.gql, got, tc.n)
		}
	}
}

// TestFieldMatrix — every searchable registry field resolves through
// the personal engine with at least one matching row where the corpus
// carries the evidence, and zero rows where it does not (the honest
// empty result is asserted too — an empty result must mean "no
// evidence", never "filter silently ignored").
func TestFieldMatrix(t *testing.T) {
	_, svc := seedMatrix(t)
	cases := []struct {
		gql string
		n   int
	}{
		{`ip="198.51.100.10"`, 1}, // dotted values are quoted strings in GQL
		{`asset_value="example.net"`, 1},
		{`asset_kind="domain"`, 1},  // a bare value that is a field name must be quoted
		{`domain="example.net"`, 2}, // domain + the hostname sharing it
		{`hostname="www.example.net"`, 1},
		{"asn=64512", 1},
		{`asn_org="AS64512 MATRIX-VANNET"`, 1},
		{`geo_country="US"`, 2}, {`geo_region=""`, 7},
		{"port=8080", 1},
		{`transport="tcp"`, 6},
		{`protocol="https"`, 4},
		{`name="https"`, 4}, // string values are ALWAYS double-quoted in GQL
		{`name="http"`, 2},
		{`http.title="Admin Dashboard"`, 1},
		{`http.server="nginx"`, 1},
		{"status=200", 3},
		{`tls.version="TLS 1.3"`, 1},
		{`tls.cert_expiry > "2026-06-01T00:00:00Z"`, 1},
		{`cert_sn="abcd1234"`, 1},
		{`cert.domain CONTAINS "example."`, 1},
		{`stale=="false"`, 7},
		{`first_seen > "2020-01-01T00:00:00Z"`, 7},
		// fields the corpus carries NO evidence for: honest zeros
		{`product="OpenSSH"`, 0},
		{`version="1.2.3"`, 0},
		{`geo_city="Mountview"`, 0},
		{`technologies CONTAINS "nginx"`, 0},
		{`cert.is_expired="true"`, 0},
	}
	for _, tc := range cases {
		if got := count(t, svc, tc.gql); got != tc.n {
			t.Errorf("query %q = %d rows, want %d", tc.gql, got, tc.n)
		}
	}
}

// TestQuotedEscapes — the lexer's escape decoding and the planner's
// LIKE escaping compose: a literal % in the PATTERN must not become a
// wildcard, and a quoted quote must round-trip.
func TestQuotedEscapes(t *testing.T) {
	_, svc := seedMatrix(t)
	// "100% up" must match ONLY "100% uptime" — against a broken
	// escape, % would act as a wildcard and also match "1000 uptime".
	if got := count(t, svc, `title CONTAINS "100% up"`); got != 1 {
		t.Errorf(`title CONTAINS "100%% up" = %d rows, want 1 (LIKE-escape contract)`, got)
	}
	if got := count(t, svc, `title *= "100? uptime"`); got != 2 {
		t.Errorf(`title *= "100? uptime" = %d rows, want 2 (? matches any single char)`, got)
	}
	// A double quote inside the value, escaped per the lexer grammar.
	if got := count(t, svc, `server="Apache"`); got != 2 {
		t.Errorf(`server="Apache" = %d rows, want 2`, got)
	}
}

// TestUnknownFieldFailsLoud — a query may never silently ignore an
// unknown field: the validator refuses it with E_QUERY_INVALID and a
// did-you-mean hint.
func TestUnknownFieldFailsLoud(t *testing.T) {
	_, svc := seedMatrix(t)
	_, err := svc.Search(context.Background(), search.Query{GQL: `nosuchfield="x"`, Limit: 10})
	if err == nil {
		t.Fatal("unknown field must fail, got nil error")
	}
	if !contains(err.Error(), "E_QUERY_INVALID") || !contains(err.Error(), "nosuchfield") {
		t.Errorf("unknown-field error must name the field and code, got: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
