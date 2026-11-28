// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package plannersqlite

// coverage_rank_test.go — R45: sorting by the `coverage` field orders by
// the DECLARED evidence-strength ladder (strongest first when :desc), not
// alphabetical class names; the keyset cursor for that sort compares the
// SAME CASE expression, so pages neither skip nor repeat rows.

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
)

func TestCoverageSortUsesEvidenceStrength(t *testing.T) {
	p := compile(t, `asset_kind == "ip"`, planner.Options{
		Sort: []planner.SortSpec{{Field: "coverage", Direction: planner.DirDesc}},
	})
	if !strings.Contains(p.SQL, "CASE \"coverage_class\"") {
		t.Fatalf("ORDER BY coverage must render the evidence-strength CASE:\n%s", p.SQL)
	}
	for _, frag := range []string{
		"WHEN 'service-observed' THEN 6",
		"WHEN 'tls-observed' THEN 5",
		"WHEN 'http-observed' THEN 4",
		"WHEN 'routing-confirmed' THEN 3",
		"WHEN 'dns-resolved' THEN 2",
		"WHEN 'discovered' THEN 1",
		"ELSE 0",
	} {
		if !strings.Contains(p.SQL, frag) {
			t.Errorf("coverage rank ladder missing %q:\n%s", frag, p.SQL)
		}
	}
	// The raw alphabetical ordering must NOT appear: sorting by
	// "coverage" renders ONLY the rank CASE (the projection list still
	// names the column, so the check is anchored to ORDER BY).
	if strings.Contains(p.SQL, `ORDER BY "coverage_class"`) {
		t.Errorf("raw alphabetical coverage sort leaked into ORDER BY:\n%s", p.SQL)
	}
}

func TestCoverageSortCursorUsesSameExpression(t *testing.T) {
	// The cursor payload carries the RANK (dns-resolved → 2), never the
	// class string — the ORDER BY and the cursor predicate compare the
	// integer CASE, so the bound value must be numeric or page 2 would
	// be empty (int CASE vs TEXT bind always compares false in SQLite).
	cur := planner.CursorPayload{
		SortField: "coverage", Value: "2", RowID: 42, RowKind: "service",
	}
	p := compile(t, `asset_kind == "ip"`, planner.Options{
		Sort:   []planner.SortSpec{{Field: "coverage", Direction: planner.DirDesc}},
		Cursor: cur.Encode(),
	})
	// The cursor predicate must compare the rank CASE, not the raw class
	// string (which would order alphabetically and skip/repeat pages).
	if !strings.Contains(p.SQL, "CASE \"coverage_class\"") {
		t.Fatalf("cursor predicate must reuse the evidence-strength CASE:\n%s", p.SQL)
	}
	bound := false
	for _, a := range p.Args {
		if n, ok := a.(int64); ok && n == 2 {
			bound = true
		}
	}
	if !bound {
		t.Errorf("cursor rank 2 not bound as an integer arg; args = %v", p.Args)
	}
	// Placeholder discipline: every ? maps to an arg.
	if got := strings.Count(p.SQL, "?"); got != len(p.Args) {
		t.Errorf("? count = %d, args = %d", got, len(p.Args))
	}
}

func TestCoverageRankLadderMatchesSQLCase(t *testing.T) {
	// The Go mapping and the SQL CASE must agree (single source of truth
	// pinned here): one representative per rung.
	for class, want := range map[string]int64{
		"service-observed": 6, "tls-observed": 5, "http-observed": 4,
		"routing-confirmed": 3, "dns-resolved": 2, "discovered": 1,
		"unclassified": 0, "some-future-class": 0,
	} {
		if got := planner.CoverageRank(class); got != want {
			t.Errorf("CoverageRank(%q) = %d, want %d", class, got, want)
		}
	}
}
