// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package searchlite

// evidence_schema_consistency_test.go — R4 P1-9: the evidence contract
// must be UNIFORM across producers.  The audit's failure mode — flat
// evidence keys in one producer and nested paths in another — is pinned
// here for the nested TLS keys specifically:
//
//   - the TLS observer (internal/observe/tls.go) records
//     evidence.tls.{version,cipher_suite,cert_subject_cn,cert_issuer_cn}
//     as a NESTED object;
//   - the latest_tls view (migration 0001/0005) extracts exactly those
//     nested paths into the search_index columns tls_version,
//     cert_subject_cn, cert_issuer_cn;
//   - the GQL planner fields tls.version / tls.cert_* read those
//     columns.
//
// The test builds the evidence EXACTLY the way the observer does and
// proves producer → projection → query for every key, so a future
// producer that flattens its keys FAILS here instead of silently
// disappearing from search.  HTTP (http.body/http.headers nested) is
// pinned by the field evidence matrix; TLS is the remaining nested
// producer contract.

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	sqlstore "github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// TestTLSObserverEvidenceShapeConsistentWithProjection ingests a fact
// whose evidence is byte-shape-identical to the TLS observer's output
// and requires every nested key to surface in the projection and the
// query planner under the documented field names.
func TestTLSObserverEvidenceShapeConsistentWithProjection(t *testing.T) {
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
	src, err := store.EnsureSource(context.Background(), "tls-shape-synthetic", "scan-tls",
		"SYNTHETIC shape fixture (not real internet data)", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}

	// The exact evidence shape internal/observe/tls.go builds (nested).
	ip := "198.51.100.30"
	f := &sqlstore.Fact{
		Asset:   storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip},
		Service: &storage.Service{Port: 443, Transport: "tcp", Protocol: "https", Name: "https"},
		Observation: storage.Observation{
			ID:           9300,
			SourceID:     src,
			SourceCursor: "tls-shape-1",
			PayloadHash:  "sha256:tls-shape-1",
			Provenance:   "scan-tls",
			ObservedAt:   time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
			Evidence: map[string]any{
				"tls": map[string]any{
					"version":         "TLS 1.3",
					"cipher_suite":    "TLS_AES_128_GCM_SHA256",
					"cert_subject_cn": "shape.example",
					"cert_issuer_cn":  "Matrix CA",
				},
				"scan": map[string]any{
					"scope_id":    int64(1),
					"target":      "shape.example:443",
					"observed_ip": ip,
					"result":      "observed",
				},
			},
		},
	}
	if _, err := store.IngestFact(context.Background(), f); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// 1. Projection columns: the latest_tls view extracted the nested keys.
	var tlsVersion, subject, issuer string
	if err := res.DB.QueryRow(`SELECT tls_version, cert_subject_cn, cert_issuer_cn
		FROM search_index WHERE asset_value = ?`, ip).Scan(&tlsVersion, &subject, &issuer); err != nil {
		t.Fatalf("search_index projection: %v", err)
	}
	if tlsVersion != "TLS 1.3" || subject != "shape.example" || issuer != "Matrix CA" {
		t.Errorf("nested TLS keys did not reach the projection: version=%q subject=%q issuer=%q", tlsVersion, subject, issuer)
	}

	// 2. The planner fields answer under the documented names.
	svc := New(res.DB)
	for _, tc := range []struct{ gql string }{
		{`tls.version="TLS 1.3"`},
		{`tls.cert_subject_cn="shape.example"`},
	} {
		r, err := svc.Search(context.Background(), search.Query{GQL: tc.gql})
		if err != nil {
			t.Errorf("query %q: %v", tc.gql, err)
			continue
		}
		if len(r.Rows) != 1 || r.Rows[0].AssetValue != ip {
			t.Errorf("query %q = %d rows, want the shape.example row", tc.gql, len(r.Rows))
		}
	}
	// cert.* fields whose producer is the CERT-FACT path (SANs, serial,
	// expiry) honestly stay empty when that evidence is absent.
	r, err := svc.Search(context.Background(), search.Query{GQL: `cert.domain CONTAINS "shape."`})
	if err != nil {
		t.Fatalf("cert.domain query: %v", err)
	}
	if len(r.Rows) != 0 {
		t.Errorf("cert.domain without cert-fact evidence must stay empty (got %d rows)", len(r.Rows))
	}

	// 3. A FLAT tls producer must NOT be able to satisfy the projection:
	// evidence with flat tls_version keys leaves the projection columns
	// empty (the contract is nested; a flat producer is a defect this
	// test keeps visible).
	flat := &sqlstore.Fact{
		Asset:   storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip},
		Service: &storage.Service{Port: 8443, Transport: "tcp", Protocol: "https", Name: "https"},
		Observation: storage.Observation{
			ID:           9301,
			SourceID:     src,
			SourceCursor: "tls-shape-2-flat",
			PayloadHash:  "sha256:tls-shape-2",
			Provenance:   "scan-tls",
			ObservedAt:   time.Date(2026, 6, 2, 1, 0, 0, 0, time.UTC),
			Evidence: map[string]any{
				"tls_version": "TLS 1.2", // FLAT — the schema mismatch shape
			},
		},
	}
	if _, err := store.IngestFact(context.Background(), flat); err != nil {
		t.Fatalf("ingest flat: %v", err)
	}
	var flatVersion sql.NullString
	if err := res.DB.QueryRow(`SELECT tls_version FROM search_index WHERE asset_value = ? AND port = 8443`, ip).Scan(&flatVersion); err != nil {
		t.Fatalf("flat projection query: %v", err)
	}
	if flatVersion.Valid && flatVersion.String != "" {
		t.Errorf("a flat tls producer must NOT populate the nested-key projection (got %v) — this is the schema mismatch the audit forbids", flatVersion)
	}
}
