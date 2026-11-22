// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package validator

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

// shorthand_free_text_test.go — v0.3.2 FOFA-style shorthand (`field:value`)
// meets the semantic layer: alias rewrite, typing, and the free-text
// expansion of bare words must behave EXACTLY as for the long forms
// (the shorthand adds a spelling, not semantics).
//
// Helpers (mustParse / mustValidate) come from the package's existing
// test files.

// comparisonStrings renders every comparison in the tree as
// "field op value" with canonical field names (post-alias-rewrite).
func comparisonStrings(t *testing.T, n ast.Node) []string {
	t.Helper()
	var out []string
	v := &allComparisons{out: &out}
	ast.Walk(v, n)
	return out
}

// allComparisons collects every Comparison (no field filter).
type allComparisons struct {
	out *[]string
}

func (c *allComparisons) Visit(n ast.Node) ast.Visitor {
	if cmp, ok := n.(*ast.Comparison); ok {
		*c.out = append(*c.out, cmp.Field+" "+cmp.Op.String()+" "+cmp.Value.String())
	}
	return c
}

// TestShorthandAliasRewrite — shorthand comparisons go through the same
// alias rewrite as the long form (`country` → geo_country).
func TestShorthandAliasRewrite(t *testing.T) {
	comps := comparisonStrings(t, mustValidate(t, "country:ID"))
	if len(comps) != 1 || comps[0] != `geo_country == "ID"` {
		t.Fatalf("country:ID → %v, want [geo_country == \"ID\"]", comps)
	}
}

// TestShorthandTyping — the shorthand value typing matches the long
// form: bare int → IntValue; quoted-numeric on an int field coerces in
// place; a bare word on an int field is a type error.
func TestShorthandTyping(t *testing.T) {
	comps := comparisonStrings(t, mustValidate(t, "port:443"))
	if len(comps) != 1 || comps[0] != "port == 443" {
		t.Fatalf("port:443 → %v, want [port == 443]", comps)
	}
	// port:"443" — quoted-numeric coercion, same node as the long form
	comps = comparisonStrings(t, mustValidate(t, "port:\"443\""))
	if len(comps) != 1 || comps[0] != "port == 443" {
		t.Fatalf(`port:"443" → %v, want [port == 443]`, comps)
	}
	// port:https — a bare word on an int field must be a GQL_E_TYPE error
	if _, ve := validate(t, "port:https"); ve == nil {
		t.Fatalf("port:https validated, want a type error")
	} else if got := ve.Detail + ve.Next; !strings.Contains(got, "takes an integer") {
		t.Errorf("port:https error = %q, want an integer-typing message", got)
	}
}

// TestShorthandUnknownField — an unknown field in a shorthand is the
// loud GQL_E_FIELD error (never an empty result): `contr:ID` errors.
func TestShorthandUnknownField(t *testing.T) {
	if _, ve := validate(t, "contr:ID"); ve == nil {
		t.Fatalf("contr:ID validated, want GQL_E_FIELD")
	} else if got := ve.Detail; !strings.Contains(got, "unknown field") || !strings.Contains(got, "contr") {
		t.Errorf("contr:ID error = %q, want an unknown-field message", got)
	}
}

// TestShorthandFreeTextOwnerTargets — the bare-word parts of the owner
// acceptance queries expand into the free-text OR-chain (one per term,
// CONTAINS over the fixed field list), while the shorthand part stays a
// plain equality — ONE contract with the documented v0.3.2 behavior.
func TestShorthandFreeTextOwnerTargets(t *testing.T) {
	// `apache` alone: 10 CONTAINS comparisons over FreeTextFields.
	comps := comparisonStrings(t, mustValidate(t, "apache"))
	if len(comps) != len(FreeTextFields) {
		t.Fatalf("apache → %d comparisons, want %d (one per free-text field)", len(comps), len(FreeTextFields))
	}
	for _, c := range comps {
		if !strings.Contains(c, "CONTAINS") || !strings.Contains(c, `"apache"`) {
			t.Errorf("free-text comparison %q lacks the term/CONTAINS", c)
		}
	}
	// `(apache || nginx) && country:ID`: 2 OR-chains (10+10) + 1 equality.
	comps = comparisonStrings(t, mustValidate(t, "(apache || nginx) && country:ID"))
	if len(comps) != 2*len(FreeTextFields)+1 {
		t.Fatalf("(apache || nginx) && country:ID → %d comparisons, want %d", len(comps), 2*len(FreeTextFields)+1)
	}
	if !hasExact(comps, `geo_country == "ID"`) {
		t.Errorf("shorthand equality missing after expansion: %v", comps)
	}
	// `(port:80 || port:443) && country:ID`: 3 equalities.
	comps = comparisonStrings(t, mustValidate(t, "(port:80 || port:443) && country:ID"))
	if len(comps) != 3 {
		t.Fatalf("(port:80 || port:443) && country:ID → %v, want 3 equalities", comps)
	}
	for _, want := range []string{"port == 80", "port == 443", `geo_country == "ID"`} {
		if !hasExact(comps, want) {
			t.Errorf("missing %q in %v", want, comps)
		}
	}
}

// TestShorthandKnownFieldStaysPresenceTest — a bare KNOWN field keeps
// the exists() semantics (bareKeywordTerm) even when OTHER comparisons
// in the query use the shorthand.
func TestShorthandKnownFieldStaysPresenceTest(t *testing.T) {
	n := mustValidate(t, "hostname && port:443")
	existsSeen := false
	v := &existsFinder{found: &existsSeen}
	ast.Walk(v, n)
	if !existsSeen {
		t.Errorf("bare known field `hostname` no longer an exists test next to a shorthand comparison")
	}
}

// existsFinder reports whether an Exists node for `hostname` survives.
type existsFinder struct {
	found *bool
}

func (f *existsFinder) Visit(n ast.Node) ast.Visitor {
	if e, ok := n.(*ast.Exists); ok && e.Field == "hostname" {
		*f.found = true
	}
	return f
}

func hasExact(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
