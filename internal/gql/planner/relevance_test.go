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

package planner

// relevance_test.go — R114 anchor walker unit tests: eligibility is
// deliberately conservative, and the tier computation is the Go twin
// of the dialect rank CASE (the cursor depends on both agreeing).

import (
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

func cmp(field string, op ast.Op, v string) *ast.Comparison {
	return &ast.Comparison{Field: field, Op: op, Value: &ast.StrValue{S: v}}
}

func TestRelevanceForEligible(t *testing.T) {
	// Single CONTAINS → anchor.
	a := RelevanceFor(cmp("product", ast.OpContains, "nginx"))
	if a == nil || a.Kind != RelContains || a.Value != "nginx" {
		t.Fatalf("anchor = %+v, want RelContains/nginx", a)
	}
	// Wildcard match with wildcards → anchor with core.
	a = RelevanceFor(cmp("hostname", ast.OpMatch, "api.*"))
	if a == nil || a.Kind != RelMatch || a.Core != "api." {
		t.Fatalf("anchor = %+v, want RelMatch core \"api.\"", a)
	}
	// AND with a non-text filter keeps the single text anchor.
	q := &ast.And{
		L: cmp("product", ast.OpContains, "nginx"),
		R: &ast.Comparison{Field: "port", Op: ast.OpEq, Value: &ast.IntValue{N: 443}},
	}
	if a := RelevanceFor(q); a == nil {
		t.Fatal("AND with an int filter must stay eligible")
	}
	// IN_DOMAIN → anchor.
	if a := RelevanceFor(cmp("domain", ast.OpInDomain, "example.com")); a == nil || a.Kind != RelInDomain {
		t.Fatalf("anchor = %+v, want RelInDomain", a)
	}
}

func TestRelevanceForIneligible(t *testing.T) {
	ineligible := map[string]ast.Node{
		"two text predicates": &ast.And{
			L: cmp("product", ast.OpContains, "nginx"),
			R: cmp("hostname", ast.OpContains, "api"),
		},
		"OR group": &ast.Or{
			L: cmp("product", ast.OpContains, "nginx"),
			R: cmp("product", ast.OpContains, "apache"),
		},
		"NOT":                                 &ast.Not{X: cmp("product", ast.OpContains, "nginx")},
		"wildcard-free match (pure equality)": cmp("hostname", ast.OpMatch, "api.example.com"),
		"int contains":                        cmp("port", ast.OpContains, "443"),
	}
	for name, q := range ineligible {
		if a := RelevanceFor(q); a != nil {
			t.Errorf("%s: got anchor %+v, want nil", name, a)
		}
	}
	if RelevanceFor(nil) != nil {
		t.Error("nil tree must yield nil")
	}
}

func TestRelevanceTier(t *testing.T) {
	contains := &RelevanceAnchor{Kind: RelContains, Value: "nginx"}
	cases := []struct {
		val  string
		want int
	}{
		{"nginx", 0}, {"NGINX", 0}, // exact, case-insensitive
		{"nginx-proxy", 1}, {"Nginx/1.2", 1}, // prefix
		{"openresty-nginx", 2}, {"", 2},
	}
	for _, c := range cases {
		if got := contains.Tier(c.val); got != c.want {
			t.Errorf("contains.Tier(%q) = %d, want %d", c.val, got, c.want)
		}
	}
	match := &RelevanceAnchor{Kind: RelMatch, Core: "api."}
	if match.Tier("api.") != 0 || match.Tier("api.example.com") != 1 {
		t.Error("match tiers wrong")
	}
	inDomain := &RelevanceAnchor{Kind: RelInDomain, Value: "example.com"}
	if inDomain.Tier("example.com") != 0 || inDomain.Tier("sub.example.com") != 1 {
		t.Error("in_domain tiers wrong")
	}
}

func TestMatchCore(t *testing.T) {
	if core, has := matchCore("api.*"); !has || core != "api." {
		t.Errorf("matchCore(\"api.*\") = %q, %v", core, has)
	}
	if core, has := matchCore("plain"); has || core != "plain" {
		t.Errorf("matchCore(\"plain\") = %q, %v", core, has)
	}
}
