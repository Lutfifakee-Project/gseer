// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package searchlite_test

// projection_regression_test.go — the v0.3.2-r2 owner finding, end to
// end on the personal (SQLite) engine over the deterministic matrix
// corpus: a custom projection (--fields) must keep the mandatory
// identity/metadata block populated, keep the selected field values,
// prune unrequested optional columns, and keep keyset pagination (the
// cursor reads row_id/row_kind/sort-value off the scanned last row)
// correct — in service AND asset mode.

import (
	"context"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/search"
)

func assertMandatoryMetadata(t *testing.T, rows []search.Row, where string) {
	t.Helper()
	for _, r := range rows {
		if r.RowID == 0 || r.RowKind != "service" || r.AssetID == 0 ||
			r.AssetKind == "" || r.AssetValue == "" {
			t.Errorf("%s: row metadata zeroed: %+v", where, r)
		}
		if r.FirstSeen.IsZero() || r.LastSeen.IsZero() {
			t.Errorf("%s: row %d timestamps zeroed (0001-01-01): first=%v last=%v",
				where, r.RowID, r.FirstSeen, r.LastSeen)
		}
	}
}

// TestProjectionKeepsMetadataRegression — the owner repro shape:
// port=443 with --fields ip,tls_version,cert_subject_cn,cert_issuer_cn.
func TestProjectionKeepsMetadataRegression(t *testing.T) {
	_, svc := seedMatrix(t)
	res, err := svc.Search(context.Background(), search.Query{
		GQL:    `port=443`,
		Fields: []string{"ip", "tls_version", "cert_subject_cn", "cert_issuer_cn"},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Rows) != 4 {
		t.Fatalf("want 4 service rows for port=443, got %d", len(res.Rows))
	}
	assertMandatoryMetadata(t, res.Rows, "custom projection")
	if res.VisibleColumns == nil {
		t.Errorf("custom projection must set Result.VisibleColumns for the tabular renderers")
	}

	foundTLS := false
	for _, r := range res.Rows {
		// Selected fields keep their values (ip is NULL-able for
		// hostname/domain assets — the index stores the bare address
		// only on ip-kind rows).
		if r.AssetKind == "ip" && r.IP == nil {
			t.Errorf("row %d: requested ip lost on an ip-kind row", r.RowID)
		}
		// Unrequested optional columns are pruned, not zero-valued.
		if r.Port != nil || r.Transport != nil || r.Domain != nil ||
			r.Product != nil || r.Technologies != nil {
			t.Errorf("row %d: unrequested column leaked: %+v", r.RowID, r)
		}
		if r.TLSCertSubjectCN != nil && *r.TLSCertSubjectCN == "www.example.net" {
			foundTLS = true
			if r.TLSVersion == nil || *r.TLSVersion != "TLS 1.3" {
				t.Errorf("TLS version: got %v, want TLS 1.3", r.TLSVersion)
			}
			if r.TLSCertIssuerCN == nil || *r.TLSCertIssuerCN != "Matrix CA" {
				t.Errorf("TLS issuer CN: got %v, want Matrix CA", r.TLSCertIssuerCN)
			}
		}
	}
	if !foundTLS {
		t.Errorf("TLS subject row missing from projection results")
	}
}

// TestProjectionTLSFilterRegression — the owner's second filter
// (tls_version!="unknown") must behave identically.
func TestProjectionTLSFilterRegression(t *testing.T) {
	_, svc := seedMatrix(t)
	res, err := svc.Search(context.Background(), search.Query{
		GQL:    `tls_version!="unknown"`,
		Fields: []string{"ip", "port"},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("no rows for tls_version!=unknown")
	}
	assertMandatoryMetadata(t, res.Rows, "tls filter projection")
	for _, r := range res.Rows {
		if r.Port == nil {
			t.Errorf("row %d: requested port lost", r.RowID)
		}
	}
}

// TestProjectionDefaultUnchanged — no --fields: the row shape must be
// exactly as before the fix (all columns populated).
func TestProjectionDefaultUnchanged(t *testing.T) {
	_, svc := seedMatrix(t)
	res, err := svc.Search(context.Background(), search.Query{GQL: `port=443`})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	assertMandatoryMetadata(t, res.Rows, "default projection")
	if res.VisibleColumns != nil {
		t.Errorf("default projection must not set VisibleColumns")
	}
	for _, r := range res.Rows {
		if r.Port == nil {
			t.Errorf("row %d: default projection lost port", r.RowID)
		}
	}
}

// TestProjectionCursorPaginationRegression — keyset pagination with a
// custom projection: the cursor must carry the real row key and sort
// value, and every page must stay metadata-complete.
func TestProjectionCursorPaginationRegression(t *testing.T) {
	_, svc := seedMatrix(t)
	ctx := context.Background()

	fields := []string{"ip"}
	page1, err := svc.Search(ctx, search.Query{GQL: `port=443`, Fields: fields, Limit: 1})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Rows) != 1 || page1.NextCursor == "" {
		t.Fatalf("page1: rows=%d cursor=%q", len(page1.Rows), page1.NextCursor)
	}
	assertMandatoryMetadata(t, page1.Rows, "page1")

	cp, err := planner.DecodeCursor(page1.NextCursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	last := page1.Rows[0]
	if cp.RowID != last.RowID || cp.RowKind != last.RowKind {
		t.Errorf("cursor row key mismatch: cursor=%d/%s row=%d/%s",
			cp.RowID, cp.RowKind, last.RowID, last.RowKind)
	}
	if cp.SortField != "last_seen" || cp.Null || cp.Value == "" {
		t.Errorf("cursor payload broken: %+v", cp)
	}

	seen := map[int64]bool{last.RowID: true}
	cursor := page1.NextCursor
	pages := 1
	for cursor != "" {
		page, err := svc.Search(ctx, search.Query{GQL: `port=443`, Fields: fields, Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		assertMandatoryMetadata(t, page.Rows, "later page")
		for _, r := range page.Rows {
			if seen[r.RowID] {
				t.Errorf("row %d repeated across pages (broken keyset)", r.RowID)
			}
			seen[r.RowID] = true
			if r.AssetKind == "ip" && r.IP == nil {
				t.Errorf("row %d: requested ip lost on a paginated page", r.RowID)
			}
		}
		cursor = page.NextCursor
		pages++
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 4 {
		t.Errorf("pagination covered %d distinct rows, want 4", len(seen))
	}
}

// TestProjectionAssetModeRegression — asset mode with a custom
// projection keeps the metadata block AND paginates correctly.
func TestProjectionAssetModeRegression(t *testing.T) {
	_, svc := seedMatrix(t)
	res, err := svc.Search(context.Background(), search.Query{
		GQL:    `port=443`,
		Mode:   "asset",
		Fields: []string{"ip"},
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("asset-mode search: %v", err)
	}
	assertMandatoryMetadata(t, res.Rows, "asset mode")
	for _, r := range res.Rows {
		if r.Port != nil {
			t.Errorf("row %d: unrequested port leaked", r.RowID)
		}
	}
	if res.VisibleColumns == nil {
		t.Errorf("asset-mode custom projection must set VisibleColumns")
	}
	if res.HasMore && res.NextCursor != "" {
		page2, err := svc.Search(context.Background(), search.Query{
			GQL: `port=443`, Mode: "asset", Fields: []string{"ip"}, Limit: 2,
			Cursor: res.NextCursor,
		})
		if err != nil {
			t.Fatalf("asset-mode page2: %v", err)
		}
		assertMandatoryMetadata(t, page2.Rows, "asset mode page2")
	}
}

// TestProjectionVisibleColumns — the tabular column contract travels
// with the result.
func TestProjectionVisibleColumns(t *testing.T) {
	_, svc := seedMatrix(t)
	res, err := svc.Search(context.Background(), search.Query{
		GQL:    `port=443`,
		Fields: []string{"ip", "tls_version"},
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	want := []string{
		"row_id", "row_kind", "asset_id", "asset_kind", "asset_value",
		"ip", "tls_version",
		"first_seen", "last_seen", "observed_at", "stale",
	}
	if len(res.VisibleColumns) != len(want) {
		t.Fatalf("VisibleColumns = %v, want %v", res.VisibleColumns, want)
	}
	for i := range want {
		if res.VisibleColumns[i] != want[i] {
			t.Errorf("VisibleColumns[%d] = %q, want %q", i, res.VisibleColumns[i], want[i])
		}
	}
}
