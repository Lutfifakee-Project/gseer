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

// R114 — search relevance.  A substring-family predicate (CONTAINS,
// the `*=` wildcard match, IN_DOMAIN) matches rows at several match
// QUALITIES: an exact value match, a prefix match, and the rest
// (substring/other).  The relevance rank orders those tiers
// exact > prefix > rest inside the SAME matched set — the matched set
// never changes, only the default ordering does.
//
// The anchor is computed from the VALIDATED tree (post alias-rewrite,
// post free-text expansion).  Eligibility is deliberately
// conservative: exactly ONE substring-family comparison in the query
// (AND-chained non-text filters are allowed); anything ambiguous —
// OR groups, NOT, quantifiers, free-text multi-field expansions,
// several text predicates — is NOT eligible and keeps the plain
// last_seen ordering.  Explicit user sorts always win.
package planner

import (
	"strings"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

// RelKind is the predicate family the anchor was derived from — it
// decides the rank tiers the dialect renders.
type RelKind int

const (
	// RelContains: `field CONTAINS "v"` — tiers: = v, LIKE v%, rest.
	RelContains RelKind = iota
	// RelMatch: `field *= "pattern"` — tiers: = core (the pattern with
	// wildcards removed), rest.  A pattern without wildcards is exact
	// equality (no tiers → never an anchor).
	RelMatch
	// RelInDomain: `field IN_DOMAIN "v"` — tiers: = v (the domain
	// itself), rest (its subdomains).
	RelInDomain
)

// RelevanceAnchor is the single substring-family predicate the
// relevance ordering is derived from.
type RelevanceAnchor struct {
	Field string // canonical field path (post-validation)
	Value string // the raw string value from the query
	// Core is the wildcard-stripped literal for RelMatch (the exact
	// candidate a row can match to reach tier 0).
	Core string
	Kind RelKind
}

// relevanceVisitor walks the tree collecting substring-family
// comparisons; any structural feature outside {Comparison, And}
// disqualifies the whole query.
type relevanceVisitor struct {
	anchors  []*RelevanceAnchor
	eligible bool
}

func (v *relevanceVisitor) visit(n ast.Node) {
	if !v.eligible {
		return
	}
	switch t := n.(type) {
	case *ast.And:
		v.visit(t.L)
		v.visit(t.R)
	case *ast.Comparison:
		a, ok := relevanceFromComparison(t)
		if !ok {
			return // a non-text comparison (filter) — harmless
		}
		v.anchors = append(v.anchors, a)
		if len(v.anchors) > 1 {
			v.eligible = false
		}
	default:
		// Or, Not, Exists, Quantified, FreeText, …: ambiguity — no
		// relevance (v1 scope; documented).
		v.eligible = false
	}
}

// numericOrTimeFields are the search fields whose columns compare as
// numbers or timestamps — a substring-family predicate over them (the
// validator normally rejects it, but the planner defends in depth)
// has no meaningful text tiers.
var numericOrTimeFields = map[string]bool{
	"port": true, "asn": true, "http.status": true,
	"first_seen": true, "last_seen": true, "last_observed": true,
	"tls.cert_expiry": true, "tls.cert_not_before": true,
	"ct.not_before": true, "ct.not_after": true, "ct.cert_timestamp": true,
	"stale": true, "is_domain": true, "is_ipv6": true, "cert.is_expired": true,
}

// relevanceFromComparison returns an anchor for a substring-family
// comparison on a string value, or ok=false.
func relevanceFromComparison(c *ast.Comparison) (*RelevanceAnchor, bool) {
	if numericOrTimeFields[c.Field] {
		return nil, false
	}
	sv, ok := c.Value.(*ast.StrValue)
	if !ok || sv.S == "" {
		return nil, false
	}
	switch c.Op {
	case ast.OpContains:
		return &RelevanceAnchor{Field: c.Field, Value: sv.S, Kind: RelContains}, true
	case ast.OpInDomain:
		return &RelevanceAnchor{Field: c.Field, Value: sv.S, Kind: RelInDomain}, true
	case ast.OpMatch:
		core, hasWild := matchCore(sv.S)
		if !hasWild {
			return nil, false // pure `*=` without wildcards is exact equality — no tiers
		}
		return &RelevanceAnchor{Field: c.Field, Value: sv.S, Core: core, Kind: RelMatch}, true
	}
	return nil, false
}

// matchCore strips wildcard characters (`*`, `?`) from a match pattern
// and reports whether any were present.  The core is the literal the
// row must equal exactly to reach tier 0.
func matchCore(s string) (core string, hasWild bool) {
	for _, r := range s {
		switch r {
		case '*', '?':
			hasWild = true
		default:
			core += string(r)
		}
	}
	return core, hasWild
}

// RelevanceFor computes the relevance anchor for a validated tree, or
// nil when the query is not relevance-eligible.  Callers pass the
// POST-VALIDATION tree (the validator's rewrites participate).
func RelevanceFor(root ast.Node) *RelevanceAnchor {
	if root == nil {
		return nil
	}
	v := &relevanceVisitor{eligible: true}
	v.visit(root)
	if !v.eligible || len(v.anchors) != 1 {
		return nil
	}
	return v.anchors[0]
}

// Tier computes the relevance tier of one row value for this anchor:
// 0 = exact, 1 = prefix (RelContains only) / rest, 2 = rest.  The
// tiers MUST stay in lockstep with the dialects' rank CASE — the
// cursor payload carries this number, and page 2 compares it against
// the same SQL expression.
func (a *RelevanceAnchor) Tier(rowVal string) int {
	switch a.Kind {
	case RelContains:
		if strings.EqualFold(rowVal, a.Value) {
			return 0
		}
		if strings.HasPrefix(strings.ToLower(rowVal), strings.ToLower(a.Value)) {
			return 1
		}
		return 2
	case RelMatch:
		if strings.EqualFold(rowVal, a.Core) {
			return 0
		}
		return 1
	case RelInDomain:
		if strings.EqualFold(rowVal, a.Value) {
			return 0
		}
		return 1
	}
	return 2
}
