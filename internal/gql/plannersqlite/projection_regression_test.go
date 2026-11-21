// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package plannersqlite

// projection_regression_test.go — the v0.3.2-r2 owner finding, SQLite
// dialect: a custom projection must always carry the identity/metadata
// and ORDER BY columns (the projection-aware scanner binds by column
// name; dropping them zeroed the row metadata and broke the cursor).

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
)

func TestProjectionAlwaysCarriesMandatoryColumnsSQLite(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{Fields: []string{"ip", "port"}})
	for _, col := range mandatoryProjectionColumns {
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

func TestProjectionIncludesSortColumnForCursorSQLite(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{
		Fields: []string{"ip"},
		Sort:   []planner.SortSpec{{Field: "port", Direction: planner.DirAsc}},
	})
	if !strings.Contains(p.SQL, `"port"`) {
		t.Errorf("sort column not projected:\n%s", p.SQL)
	}
	p2 := compile(t, `port == 443`, planner.Options{Fields: []string{"ip"}})
	if !strings.Contains(p2.SQL, `"last_seen"`) {
		t.Errorf("default sort column not projected:\n%s", p2.SQL)
	}
}

func TestDefaultProjectionSQLUnchangedSQLite(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{})
	for _, col := range allSearchColumns {
		if !strings.Contains(p.SQL, `"`+col+`"`) {
			t.Errorf("default SQL missing canonical column %q:\n%s", col, p.SQL)
		}
	}
}

func TestAssetModeOuterProjectionCarriesMetadataSQLite(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{Mode: planner.ModeAsset, Fields: []string{"ip"}})
	outer := p.SQL[strings.LastIndex(p.SQL, "SELECT "):]
	for _, col := range []string{"row_id", "row_kind", "asset_id", "asset_kind", "asset_value", "first_seen", "last_seen"} {
		if !strings.Contains(outer, `"`+col+`"`) {
			t.Errorf("asset-mode outer select missing %q:\n%s", col, outer)
		}
	}
}
