// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package searchlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/fprule"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// http_body_headers_integration_test.go — the v0.3.2 HTTP fingerprint
// fields END-TO-END on the personal engine: the observer's body/header
// evidence ($.http.body / $.http.headers) flows through the 0007
// search_index columns, the GQL `body` / `header` fields execute real
// evidence matching (including the shorthand and projection), and the
// CMS fingerprint rules classify WordPress into technologies[] at
// ingest so `tech CONTAINS wordpress` finds it.
func TestHTTPBodyHeaderFieldsE2E(t *testing.T) {
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
	// Attach the SEED fingerprint registry exactly like personal mode
	// does (SetFingerprintEngine) — the CMS rules classify at ingest.
	rules, problems, rerr := fprule.LoadSeed()
	if rerr != nil {
		t.Fatalf("load seed rules: %v", rerr)
	}
	if len(problems) != 0 {
		t.Fatalf("seed lint problems: %v", problems)
	}
	store.SetFingerprintEngine(fprule.NewRegistry(rules))

	src, err := store.EnsureSource(context.Background(), "fixture", "fixture", "", nil)
	if err != nil {
		t.Fatalf("fixture source: %v", err)
	}
	ip := "203.0.113.77"
	wpBody := `<html><head><link rel="stylesheet" href="https://blog.example.test/wp-content/themes/twenty/style.css">` +
		`<script src="/wp-includes/js/jquery.min.js"></script><title>My Blog</title></head><body>hello</body></html>`
	wpEvidence := map[string]any{
		"http": map[string]any{
			"status":  200,
			"title":   "My Blog",
			"server":  "nginx",
			"body":    wpBody,
			"headers": "Server: nginx\nX-Pingback: https://blog.example.test/xmlrpc.php",
		},
	}
	plainEvidence := map[string]any{
		"http": map[string]any{
			"status":  200,
			"title":   "How to speed up WordPress sites",
			"server":  "nginx",
			"body":    "<html><body>An article ABOUT WordPress, no markers.</body></html>",
			"headers": "Server: nginx",
		},
	}
	facts := []storage.Fact{
		{Asset: storage.Asset{Kind: "ip", Value: ip, IP: &ip},
			Service: &storage.Service{Port: 443, Transport: "tcp", Protocol: "https", Product: "nginx"},
			Observation: storage.Observation{ID: 101, SourceID: src, SourceCursor: "wp-443",
				PayloadHash: "hash-wp-443", Provenance: "fixture",
				ObservedAt: time.Now().UTC(), Evidence: wpEvidence}},
		{Asset: storage.Asset{Kind: "ip", Value: ip, IP: &ip},
			Service: &storage.Service{Port: 8080, Transport: "tcp", Protocol: "http", Product: "nginx"},
			Observation: storage.Observation{ID: 102, SourceID: src, SourceCursor: "plain-8080",
				PayloadHash: "hash-plain-8080", Provenance: "fixture",
				ObservedAt: time.Now().UTC(), Evidence: plainEvidence}},
	}
	st, err := store.IngestFacts(context.Background(), facts)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if st.ObservationsInserted != 2 {
		t.Fatalf("ingest stats = %+v", st)
	}

	svc := New(res.DB)
	cases := []struct {
		gql      string
		rows     int
		wantPort int
	}{
		// the body evidence matches the REAL WordPress markers
		{`body CONTAINS "wp-content"`, 1, 443},
		{`body CONTAINS "wp-includes"`, 1, 443},
		// the header evidence matches the real X-Pingback header
		{`header CONTAINS "X-Pingback"`, 1, 443},
		// the article ABOUT WordPress does NOT match (honest negative)
		{`body CONTAINS "wp-admin"`, 0, 0},
		// the shorthand spelling is the same query
		{`body:"wp-includes"`, 1, 443},
		{`header:"X-Pingback"`, 1, 443},
		// wildcard works over the body surface
		{`body *= "*wp-includes*"`, 1, 443},
		// CMS fingerprint classification from body/header evidence at ingest
		{`tech CONTAINS "wordpress"`, 1, 443},
		// the non-WordPress row carries no cms fingerprint
		{`tech CONTAINS "nginx" && port==8080`, 1, 8080},
	}
	for _, tc := range cases {
		res, err := svc.Search(context.Background(), search.Query{GQL: tc.gql})
		if err != nil {
			t.Fatalf("Search(%q): %v", tc.gql, err)
		}
		if len(res.Rows) != tc.rows {
			t.Errorf("%q = %d rows, want %d", tc.gql, len(res.Rows), tc.rows)
			continue
		}
		if tc.rows == 1 && tc.wantPort != 0 && res.Rows[0].Port != nil && *res.Rows[0].Port != tc.wantPort {
			t.Errorf("%q hit port %d, want %d", tc.gql, *res.Rows[0].Port, tc.wantPort)
		}
	}

	// Projection: the body/header fields are addressable via --fields.
	res2, err := svc.Search(context.Background(), search.Query{GQL: `body CONTAINS "wp-content"`})
	if err != nil {
		t.Fatalf("projection search: %v", err)
	}
	row := res2.Rows[0]
	if row.HTTPBody == nil || !strings.Contains(*row.HTTPBody, "wp-content") {
		t.Errorf("projected http_body missing the body evidence: %v", row.HTTPBody)
	}
	if row.HTTPHeader == nil || !strings.Contains(*row.HTTPHeader, "X-Pingback") {
		t.Errorf("projected http_header missing the header evidence: %v", row.HTTPHeader)
	}
}
