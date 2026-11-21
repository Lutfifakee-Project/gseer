// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/search"
)

// t1 is the shared fixture timestamp (RFC3339, UTC).
var t1 = time.Date(2026, 11, 19, 8, 30, 0, 0, time.UTC)

// r3.2 finding #1 regression tests — the terminal table renderer must
// honor the custom projection contract: under --fields the table shows
// the projected columns (same header and cell semantics as CSV), an
// absent field renders honestly empty (never a fabricated value), and
// the default table (no --fields) keeps the historical single-line
// service-summary form byte-compatible.

func renderResultString(t *testing.T, res *search.Result, format string) string {
	t.Helper()
	var buf bytes.Buffer
	renderResult(&buf, res, format)
	return buf.String()
}

func tableProjectedCell(t *testing.T, out, col string) string {
	t.Helper()
	lines := strings.Split(out, "\n")
	// The header is the first line whose fields contain the leading
	// identity column ("row_id") — above it sits the count line (and
	// possibly a notice line).
	headerIdx := -1
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "row_id ") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 || headerIdx+2 > len(lines) {
		t.Fatalf("projected table header not found in %q", out)
	}
	headers := strings.Fields(lines[headerIdx])
	idx := -1
	for i, h := range headers {
		if h == col {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("column %q not in header %v", col, headers)
	}
	// The rule line (dashes) encodes each column's exact width — the
	// renderer emits width dashes per column, two-space separated.
	var widths []int
	for _, seg := range strings.Split(strings.TrimRight(lines[headerIdx+1], " "), "  ") {
		widths = append(widths, len(seg))
	}
	if len(widths) != len(headers) {
		t.Fatalf("rule line width mismatch: %d vs %d headers", len(widths), len(headers))
	}
	// First data row.
	ln := lines[headerIdx+2]
	off := 0
	for i := range headers {
		end := off + widths[i]
		if end > len(ln) {
			end = len(ln)
		}
		if i == idx {
			return strings.TrimSpace(ln[min(off, len(ln)):end])
		}
		off += widths[i] + 2
	}
	return ""
}

func projectionFixture(fields []string, mutate func(*search.Row)) *search.Result {
	row := search.Row{
		RowID:      15,
		RowKind:    "service",
		AssetID:    12,
		AssetKind:  "ip",
		AssetValue: "203.0.113.10",
	}
	if mutate != nil {
		mutate(&row)
	}
	return &search.Result{
		Rows: []search.Row{row},
		Query: search.QueryInfo{
			GQL:       "port=443",
			Mode:      "service",
			Branch:    "scan",
			Limit:     20,
			TimeoutMs: 250,
			Sort:      []planner.SortSpec{{Field: "last_seen", Direction: planner.DirDesc}},
			TookMs:    3,
			RowCount:  1,
			Fixtures:  true,
		},
		Notice:         "",
		VisibleColumns: search.VisibleColumns(fields),
	}
}

func TestTableDefaultKeepsServiceSummary(t *testing.T) {
	res := &search.Result{
		Rows: []search.Row{{
			RowID: 15, RowKind: "service", AssetID: 12, AssetKind: "ip",
			AssetValue: "203.0.113.10",
			Port:       ptr2(443), Transport: ptr2s("tcp"), Protocol: ptr2s("https"),
			FirstSeen: t1, LastSeen: t1,
		}},
		Query: search.QueryInfo{RowCount: 1, TookMs: 3, Mode: "service"},
	}
	out := renderResultString(t, res, "table")
	if !strings.Contains(out, "1 result(s) in 3 ms  (mode=service)") {
		t.Fatalf("default table count line drifted: %q", out)
	}
	want := "  " + rowLine(res.Rows[0])
	if !strings.Contains(out, want) {
		t.Fatalf("default table row not byte-compatible with rowLine:\n got %q\nwant %q", out, want)
	}
	if !strings.Contains(out, ":443/tcp") || !strings.Contains(out, "https") {
		t.Fatalf("default table lost the service summary: %q", out)
	}
}

func TestTableCustomProjectionTLSColumns(t *testing.T) {
	fields := []string{"ip", "tls_version", "cert_subject_cn", "cert_issuer_cn"}
	res := projectionFixture(fields, func(r *search.Row) {
		r.IP = ptr2s("203.0.113.10")
		r.TLSVersion = ptr2s("TLSv1.3")
		r.TLSCertSubjectCN = ptr2s("example.com")
		r.TLSCertIssuerCN = ptr2s("R3")
		r.FirstSeen, r.LastSeen = t1, t1
	})
	out := renderResultString(t, res, "table")
	for _, col := range fields {
		if !strings.HasPrefix(out, col) && !strings.Contains(out, col) {
			t.Fatalf("header missing projected column %q: %q", col, out)
		}
	}
	for _, want := range []string{"203.0.113.10", "TLSv1.3", "example.com", "R3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table lost TLS data %q that JSON proves exists: %q", want, out)
		}
	}
	if strings.Contains(out, "-/-") {
		t.Fatalf("table still renders the fabricated '-/-' service summary under --fields: %q", out)
	}
}

func TestTableCustomProjectionServiceFields(t *testing.T) {
	fields := []string{"ip", "port", "transport", "protocol"}
	res := projectionFixture(fields, func(r *search.Row) {
		r.IP = ptr2s("203.0.113.10")
		r.Port = ptr2(443)
		r.Transport = ptr2s("tcp")
		r.Protocol = ptr2s("https")
		r.FirstSeen, r.LastSeen = t1, t1
	})
	out := renderResultString(t, res, "table")
	for _, want := range []string{"203.0.113.10", "443", "tcp", "https"} {
		if !strings.Contains(out, want) {
			t.Fatalf("requested service field %q missing from table: %q", want, out)
		}
	}
	if got := tableProjectedCell(t, out, "port"); got != "443" {
		t.Fatalf("port cell = %q, want 443", got)
	}
}

func TestTableMissingFieldHonest(t *testing.T) {
	fields := []string{"ip", "tls_version", "cert_subject_cn"}
	res := projectionFixture(fields, func(r *search.Row) {
		r.IP = ptr2s("203.0.113.10")
		// tls_version and tls_cert_subject_cn NOT present on this row.
		r.FirstSeen, r.LastSeen = t1, t1
	})
	out := renderResultString(t, res, "table")
	if got := tableProjectedCell(t, out, "tls_version"); got != "" {
		t.Fatalf("absent tls_version rendered %q — must be honestly empty, got table: %q", got, out)
	}
	if got := tableProjectedCell(t, out, "cert_subject_cn"); got != "" {
		t.Fatalf("absent tls_cert_subject_cn rendered %q — must be honestly empty: %q", got, out)
	}
	if got := tableProjectedCell(t, out, "ip"); got != "203.0.113.10" {
		t.Fatalf("present ip cell = %q: %q", got, out)
	}
}

func TestTableAssetModeAndServiceMode(t *testing.T) {
	fields := []string{"ip", "port"}
	res := &search.Result{
		Rows: []search.Row{
			{RowID: 15, RowKind: "service", AssetID: 12, AssetKind: "ip",
				AssetValue: "203.0.113.10", IP: ptr2s("203.0.113.10"), Port: ptr2(443),
				FirstSeen: t1, LastSeen: t1},
			{RowID: 16, RowKind: "asset-only", AssetID: 13, AssetKind: "domain",
				AssetValue: "example.com", Domain: ptr2s("example.com"),
				FirstSeen: t1, LastSeen: t1},
		},
		Query:          search.QueryInfo{RowCount: 2, TookMs: 3, Mode: "asset"},
		VisibleColumns: search.VisibleColumns(fields),
	}
	out := renderResultString(t, res, "table")
	if !strings.Contains(out, "mode=asset") {
		t.Fatalf("mode line lost: %q", out)
	}
	if got := tableProjectedCell(t, out, "port"); got != "443" {
		t.Fatalf("service row port cell = %q: %q", got, out)
	}
	if !strings.Contains(out, "example.com") {
		t.Fatalf("asset row asset_value missing: %q", out)
	}
	// The asset-only row must not borrow a fabricated port.
	if strings.Contains(out, ":443/") {
		t.Fatalf("asset mode fabricated a service summary: %q", out)
	}
}

func ptr2(n int) *int        { return &n }
func ptr2s(s string) *string { return &s }
