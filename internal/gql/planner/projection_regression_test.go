// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package planner

// projection_regression_test.go — the v0.3.2-r2 owner finding: a custom
// projection (--fields) used to drop the identity/metadata and ORDER BY
// columns from the SELECT, zeroing the row metadata (row_id/row_kind/
// asset_*/first_seen/last_seen = 0/""/0001-01-01) and corrupting the
// keyset cursor.  The planner now ALWAYS carries them; these tests pin
// the invariant at the SQL layer.

import (
	"strings"
	"testing"
)

func TestProjectionAlwaysCarriesMandatoryColumns(t *testing.T) {
	p := compile(t, `port == 443`, Options{Fields: []string{"ip", "port"}})
	for _, col := range MandatoryProjectionColumns() {
		if !strings.Contains(p.SQL, `"`+col+`"`) {
			t.Errorf("custom projection SQL missing mandatory column %q:\n%s", col, p.SQL)
		}
	}
	for _, col := range []string{`"ip"`, `"port"`} {
		if !strings.Contains(p.SQL, col) {
			t.Errorf("custom projection SQL missing requested column %s:\n%s", col, p.SQL)
		}
	}
}

func TestProjectionIncludesSortColumnForCursor(t *testing.T) {
	// A sort column outside the requested fields must still be projected
	// — cursorFromRow reads the sort value off the scanned last row.
	p := compile(t, `port == 443`, Options{
		Fields: []string{"ip"},
		Sort:   []SortSpec{{Field: "port", Direction: DirAsc}},
	})
	if !strings.Contains(p.SQL, `"port"`) {
		t.Errorf("sort column not projected:\n%s", p.SQL)
	}
	// The default sort (last_seen DESC) is part of the mandatory block.
	p2 := compile(t, `port == 443`, Options{Fields: []string{"ip"}})
	if !strings.Contains(p2.SQL, `"last_seen"`) {
		t.Errorf("default sort column not projected:\n%s", p2.SQL)
	}
}

func TestProjectionNoDuplicateMandatoryColumn(t *testing.T) {
	p := compile(t, `port == 443`, Options{Fields: []string{"ip", "last_seen"}})
	selectList := p.SQL[:strings.Index(p.SQL, " FROM")]
	if n := strings.Count(selectList, `"last_seen"`); n != 1 {
		t.Errorf("last_seen appears %d times in the select list, want exactly 1:\n%s", n, selectList)
	}
}

func TestDefaultProjectionSQLUnchanged(t *testing.T) {
	// The r2 fix only augments CUSTOM projections: the default (no
	// --fields) SQL must keep the plain allSearchColumns select list.
	p := compile(t, `port == 443`, Options{})
	for _, col := range AllSearchColumns() {
		if !strings.Contains(p.SQL, `"`+col+`"`) {
			t.Errorf("default SQL missing canonical column %q:\n%s", col, p.SQL)
		}
	}
}

func TestAssetModeOuterProjectionCarriesMetadata(t *testing.T) {
	p := compile(t, `port == 443`, Options{Mode: ModeAsset, Fields: []string{"ip"}})
	// The OUTER select (after the page CTE) is what the scanner reads.
	outer := p.SQL[strings.LastIndex(p.SQL, "SELECT "):]
	for _, col := range []string{"row_id", "row_kind", "asset_id", "asset_kind", "asset_value", "first_seen", "last_seen"} {
		if !strings.Contains(outer, `"`+col+`"`) {
			t.Errorf("asset-mode outer select missing %q:\n%s", col, outer)
		}
	}
}

func TestResolveProjectionColumnExported(t *testing.T) {
	if got := ResolveProjectionColumn("tls.version"); got != "tls_version" {
		t.Errorf("canonical path: got %q", got)
	}
	if got := ResolveProjectionColumn("tls_version"); got != "tls_version" {
		t.Errorf("column spelling: got %q", got)
	}
	if got := ResolveProjectionColumn("nope_nope"); got != "" {
		t.Errorf("unknown name: got %q", got)
	}
	// Bookkeeping columns resolve through resolveProjection's allow-list,
	// not the registry — ResolveProjectionColumn answers "" for them
	// (they are mandatory, so the pruning layer never needs them).
	if got := ResolveProjectionColumn("row_id"); got != "" {
		t.Errorf("bookkeeping column is not a registry column: got %q", got)
	}
}
