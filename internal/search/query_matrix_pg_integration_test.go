// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build integration

package search

// query_matrix_pg_integration_test.go — the PostgreSQL mirror of the
// personal engine's query matrix (searchlite/query_matrix_test.go): the
// SAME deterministic corpus, ingested through postgres.Store, searched
// through the PG SearchService on BOTH supported majors (the harness
// honors GSEER_TEST_PG_ADMIN — CI points it at 16 and 17 in turn).
//
// The corpus uses TEST-NET / example.* documentation values only; it is
// a fixture, not a discovery claim.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/postgres"
)

var matrixSeq int64

// pgSeedMatrix ingests the matrix corpus (7 rows; see the SQLite twin
// for the full row table) into a fresh PG index.
func pgSeedMatrix(t *testing.T) (*Service, func()) {
	t.Helper()
	dsn, dbCleanup := sIntTestDB(t)
	if _, err := postgres.BootstrapRoles(context.Background(), dsn); err != nil {
		dbCleanup()
		t.Fatalf("BootstrapRoles: %v", err)
	}
	if _, _, err := postgres.RunMigrations(dsn, 1001); err != nil {
		dbCleanup()
		t.Fatalf("migrate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		dbCleanup()
		t.Fatalf("pool: %v", err)
	}
	store := postgres.NewStore(pool)
	src, err := store.EnsureSource(context.Background(), "fixture", "fixture", "", nil)
	if err != nil {
		pool.Close()
		dbCleanup()
		t.Fatalf("fixture source: %v", err)
	}
	t0 := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	type row struct {
		kind, value, domain, country, title, server string
		port                                        int
		protocol                                    string
		tls                                         map[string]any
		at                                          time.Time
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
	for _, rw := range rows {
		var f postgres.Fact
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
			SourceCursor: "matrix-" + rw.value,
			PayloadHash:  time.Now().UTC().Format("matrix-20060102T150405.000000000"),
			Provenance:   storage.ProvenanceFixture,
			ObservedAt:   rw.at,
		}
		// every row needs a caller-assigned observation id (PG has no
		// default and zero ids collide on the delivery identity)
		matrixSeq++
		f.Observation.PayloadHash = "matrix-hash-" + rw.value
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
			pool.Close()
			dbCleanup()
			t.Fatalf("ingest %s: %v", rw.value, err)
		}
	}
	return New(pool), func() { pool.Close(); dbCleanup() }
}

func pgCount(t *testing.T, svc *Service, gql string) int {
	t.Helper()
	res, err := svc.Search(context.Background(), Query{GQL: gql, Limit: 300})
	if err != nil {
		t.Fatalf("search %q: %v", gql, err)
	}
	return len(res.Rows)
}

// TestPGQueryMatrix — the operator/field/alias matrix on PostgreSQL
// (same expectations as the SQLite twin; the engines are contract-bound
// to behave identically for every feature the personal engine supports).
func TestPGQueryMatrix(t *testing.T) {
	svc, cleanup := pgSeedMatrix(t)
	defer cleanup()
	cases := []struct {
		gql string
		n   int
	}{
		{"port=443", 4}, {"port==443", 4}, {`port="443"`, 4},
		{"port != 443", 2}, {`port != "443"`, 2},
		{"port >= 80 && port <= 443", 5}, {"port > 443", 1}, {"port < 443", 1},
		{"port <= 80", 1}, {"asn >= 64512", 1}, {"asn < 64512", 6},
		{`protocol="https" && port=443`, 4},
		{`port=80 || port=8080`, 2},
		{`!(protocol="https")`, 2},
		{`!(port=443 || port=80)`, 1},
		{`(port=80 || port=8080) && country="DE"`, 2},
		{`! (country="US")`, 5}, // missing geo is '' (not NULL) → negates to TRUE
		{"port IN (80, 8080)", 2}, {`port IN (80, "443")`, 5}, {`country IN ("US", "DE")`, 4},
		{`ip IN_CIDR "198.51.100.0/24"`, 4}, {`ip IN_CIDR "2001:db8::/32"`, 1},
		{`ip IN_CIDR "203.0.113.0/24"`, 0},
		{`hostname *= "*.example.net"`, 1}, {`asset_value *= "198.51.100.*"`, 4},
		{`title CONTAINS "Dashboard"`, 1}, {`title CONTAINS "100% up"`, 1},
		{`server CONTAINS "apache"`, 2},
		{`domain IN_DOMAIN "example.net"`, 2},
		{"exists(port)", 6}, {"exists(http.title)", 3}, {"exists(cert_expiry)", 1},
		{`"dashboard"`, 1}, {"dashboard", 1},
		{`http.title=""`, 4}, {`server!=""`, 3},
		{`last_seen > "2026-01-01T00:00:00Z"`, 7},
		{`after="2026-01-15"`, 7}, {`before="2030-01-01"`, 7},
		{`is_domain="true"`, 2}, {`is_ipv6="true"`, 1}, {`cert.is_expired="false"`, 1},
		{`host="www.example.net"`, 1}, {`host="198.51.100.10"`, 1},
		{`stale=="false"`, 7}, {`stale=="true"`, 0}, {`stale != "false"`, 0},
		// observed_at: the REAL evidence time (migration 0022)
		{`observed_at > "2026-01-15T00:30:00Z"`, 5},
		{`observed_at < "2026-01-15T00:00:00Z"`, 1},
		{`observed_at >= "2026-01-15T00:00:00Z" && observed_at <= "2026-01-15T01:00:00Z"`, 2},
		{`exists(observed_at)`, 7},
		// compat aliases
		{`cert.issuer="Matrix CA"`, 1}, {`cert.issuer CONTAINS "Matrix"`, 1},
		{`cert.subject="www.example.net"`, 1},
		{`organization CONTAINS "MATRIX"`, 1},
		// field coverage
		{`ip="198.51.100.10"`, 1}, {`asset_value="example.net"`, 1},
		{`asset_kind="domain"`, 1}, {`domain="example.net"`, 2},
		{`hostname="www.example.net"`, 1}, {"asn=64512", 1},
		{`asn_org="AS64512 MATRIX-VANNET"`, 1},
		{`geo_country="US"`, 2}, {`geo_region=""`, 7},
		{"port=8080", 1}, {`transport="tcp"`, 6}, {`protocol="https"`, 4},
		{`name="https"`, 4}, {`name="http"`, 2},
		{`http.title="Admin Dashboard"`, 1}, {`http.server="nginx"`, 1},
		{"status=200", 3}, {`tls.version="TLS 1.3"`, 1},
		{`tls.cert_expiry > "2026-06-01T00:00:00Z"`, 1},
		{`cert_sn="abcd1234"`, 1}, {`cert.domain CONTAINS "example."`, 1},
		{`first_seen > "2020-01-01T00:00:00Z"`, 7},
		{`product="OpenSSH"`, 0}, {`version="1.2.3"`, 0},
		{`geo_city="Mountview"`, 0}, {`technologies CONTAINS "nginx"`, 0},
		{`cert.is_expired="true"`, 0},
	}
	for _, tc := range cases {
		if got := pgCount(t, svc, tc.gql); got != tc.n {
			t.Errorf("query %q = %d rows, want %d", tc.gql, got, tc.n)
		}
	}
}

// TestPGObservedAtRowProjection — the JSON row carries observed_at with
// the REAL evidence time, distinct from the ingest-stamped last_seen.
func TestPGObservedAtRowProjection(t *testing.T) {
	svc, cleanup := pgSeedMatrix(t)
	defer cleanup()
	res, err := svc.Search(context.Background(), Query{GQL: `ip="198.51.100.10"`, Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	r := res.Rows[0]
	if r.ObservedAt == nil {
		t.Fatal("row.observed_at is NULL, want the ingested evidence time")
	}
	want := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if !r.ObservedAt.Equal(want) {
		t.Errorf("observed_at = %v, want %v (the evidence time, not the ingest stamp)", r.ObservedAt.UTC(), want)
	}
	if r.LastSeen.Before(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("last_seen = %v, want the ingest stamp (~test run time)", r.LastSeen)
	}
}
