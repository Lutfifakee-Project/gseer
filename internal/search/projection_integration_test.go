// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build integration

package search

// projection_integration_test.go — the v0.3.2-r2 owner finding against
// real PostgreSQL: a custom projection keeps the mandatory identity/
// metadata block populated, prunes unrequested optional columns, and
// keyset pagination with --fields stays correct.

import (
	"context"
	"testing"
)

func TestSearchProjectionMetadataAndCursorPG(t *testing.T) {
	svc, cleanup := sIntSetup(t)
	defer cleanup()
	ctx := context.Background()

	fields := []string{"ip", "tls_version", "cert_subject_cn"}
	res, err := svc.Search(ctx, Query{GQL: `port == 443`, Fields: fields})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("no rows for port == 443")
	}
	for _, r := range res.Rows {
		if r.RowID == 0 || r.RowKind != "service" || r.AssetID == 0 ||
			r.AssetKind == "" || r.AssetValue == "" {
			t.Errorf("row metadata zeroed: %+v", r)
		}
		if r.FirstSeen.IsZero() || r.LastSeen.IsZero() {
			t.Errorf("row %d: timestamps zeroed", r.RowID)
		}
		if r.IP == nil {
			t.Errorf("row %d: requested ip lost", r.RowID)
		}
		if r.Port != nil || r.Transport != nil || r.Protocol != nil {
			t.Errorf("row %d: unrequested column leaked: %+v", r.RowID, r)
		}
	}

	// The fixture corpus carries TLS evidence on 203.0.113.10:443 — the
	// selected tls_version must keep its real value there.
	found := false
	for _, r := range res.Rows {
		if r.TLSCertSubjectCN != nil && *r.TLSCertSubjectCN == "a.example.com" {
			found = true
			if r.TLSVersion == nil || *r.TLSVersion == "" {
				t.Errorf("TLS version lost on the TLS row")
			}
		}
	}
	if !found {
		t.Errorf("fixture TLS row missing from projection results")
	}

	// Keyset pagination with the custom projection: every page stays
	// metadata-complete, no row repeats.
	seen := map[int64]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := svc.Search(ctx, Query{GQL: `port == 443`, Fields: fields, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		if pages > 0 && len(page.Rows) == 0 {
			break
		}
		for _, r := range page.Rows {
			if r.RowID == 0 || r.RowKind != "service" || r.AssetValue == "" || r.FirstSeen.IsZero() {
				t.Errorf("page %d: metadata zeroed: %+v", pages+1, r)
			}
			if seen[r.RowID] {
				t.Errorf("row %d repeated across pages", r.RowID)
			}
			seen[r.RowID] = true
		}
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		if !page.HasMore {
			break
		}
		cursor = page.NextCursor
		pages++
	}
	if len(seen) < 2 {
		t.Errorf("pagination covered %d rows, want >= 2", len(seen))
	}
}
