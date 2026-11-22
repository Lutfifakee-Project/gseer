// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package parser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

// shorthand_test.go — the v0.3.2 FOFA-style `field:value` shorthand
// (docs/audit/V032-SEARCH-SYNTAX-AUDIT.md §3, §5).  The shorthand adds a
// SPELLING, not semantics: every node it builds must be identical to the
// node the long form `field == value` builds, and every owner acceptance
// target must parse to the documented tree.

// TestParseShorthandEquivalence — shorthand and long form build the SAME
// canonical tree (compatible by construction: the validator and the two
// planners only ever see the long-form node).
func TestParseShorthandEquivalence(t *testing.T) {
	// Bare-word shorthand values have no bare long form (GQL long form
	// requires operators; dotted/bare values are quoted strings) — the
	// equivalent long form is the quoted string.
	cases := []struct{ short, long string }{
		{"port:443", "port == 443"},
		{"port:\"443\"", `port == "443"`},
		{"country:ID", `country == "ID"`},
		{"country:\"ID\"", `country == "ID"`},
		{"domain:example.com", `domain == "example.com"`},
		{"title:\"login page\"", `title == "login page"`},
		{"host:www.example.com", `host == "www.example.com"`},
		{"asn:13335", "asn == 13335"},
		{"ip:\"203.0.113.10\"", `ip == "203.0.113.10"`},
		{"product:apache", `product == "apache"`},
	}
	for _, c := range cases {
		long := mustParse(t, c.long).String()
		short := mustParse(t, c.short).String()
		if short != long {
			t.Errorf("shorthand %q → %s, long form %q → %s (must be identical)", c.short, short, c.long, long)
		}
	}
}

// TestParseShorthandValueForms — the three value grammars the shorthand
// accepts: INT, STRING, bare IDENT word.  Canonical rendering check.
func TestParseShorthandValueForms(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"port:443", "port == 443"},
		{"port:8080", "port == 8080"},
		{"country:ID", "country == \"ID\""},
		{"domain:example.com", "domain == \"example.com\""},
		{"title:\"Login Page\"", `title == "Login Page"`},
	}
	for _, c := range cases {
		got := mustParse(t, c.src).String()
		if got != c.want {
			t.Errorf("Parse(%q).String() = %s, want %s", c.src, got, c.want)
		}
	}
}

// TestParseShorthandOwnerTargets — the five owner acceptance queries
// (R1 in docs/audit/V032-SEARCH-SYNTAX-AUDIT.md) parse to their
// documented canonical trees.  PARSER level: an unquoted bare word is an
// ast.Exists leaf (the validator expands it into the free-text OR-chain
// — that contract is pinned in the validator's shorthand tests).
func TestParseShorthandOwnerTargets(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		// free text (single bare word) — Exists at parse level
		{"apache", "exists(apache)"},
		// shorthand AND free text
		{"port:443 && apache", "(port == 443 && exists(apache))"},
		// free-text OR
		{"apache || nginx", "(exists(apache) || exists(nginx))"},
		// parens + shorthand
		{"(apache || nginx) && country:ID", "((exists(apache) || exists(nginx)) && country == \"ID\")"},
		// precedence + parens + shorthand, both sides of ||
		{"(port:80 || port:443) && country:ID", "((port == 80 || port == 443) && country == \"ID\")"},
	}
	for _, c := range cases {
		got := mustParse(t, c.src).String()
		if got != c.want {
			t.Errorf("Parse(%q).String() =\n  %s\nwant:\n  %s", c.src, got, c.want)
		}
	}
}

// TestParseShorthandMixedWithGrammar — shorthand composes with the FULL
// existing grammar: operators, keyword forms, negation, IN, wildcards,
// quantifiers, nested parens.
func TestParseShorthandMixedWithGrammar(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{"port:443 && protocol:https", "(port == 443 && protocol == \"https\")"},
		{"not port:22", "!(port == 22)"},
		{"port:443 && server*=\"nginx*\"", "(port == 443 && server *= \"nginx*\")"},
		{"port IN (80, 443) && country:ID", "(port IN (80, 443) && country == \"ID\")"},
		{"ANY(service){ port:443 && protocol:https }", "ANY(service){ (port == 443 && protocol == \"https\") }"},
		{"(port:80 || port:443) && (country:ID || country:SG)", "((port == 80 || port == 443) && (country == \"ID\" || country == \"SG\"))"},
		{"port:443 and title:\"admin\"", "(port == 443 && title == \"admin\")"}, // keyword AND + shorthand
		{"status:200 && country:US", "(status == 200 && country == \"US\")"},    // int shorthand on alias field
	}
	for _, c := range cases {
		got := mustParse(t, c.src).String()
		if got != c.want {
			t.Errorf("Parse(%q).String() =\n  %s\nwant:\n  %s", c.src, got, c.want)
		}
	}
}

// TestParseShorthandMalformed — every malformed shorthand is a loud
// GQL_E_PARSE with a concrete hint (no silent fallback).
func TestParseShorthandMalformed(t *testing.T) {
	cases := []struct {
		src    string
		inHint []string // substrings the Next/Detail hint must contain
	}{
		{"port:", []string{"missing value after ':'", "port:443"}},
		{"port: && apache", []string{"unexpected", "port:443"}},
		{"port:(443", []string{"unexpected"}},
		{"country:in", []string{"unexpected"}},                    // keyword lexeme is not a bare-word value
		{"country:and", []string{"unexpected"}},                   // ditto
		{"port:443:8080", []string{"unexpected", "end of query"}}, // one shorthand per comparison
		{":443", []string{"unexpected"}},                          // no field before ':'
	}
	for _, c := range cases {
		pe := parseErr(t, c.src)
		msg := pe.Detail + " | " + pe.Next
		for _, frag := range c.inHint {
			if !strings.Contains(msg, frag) {
				t.Errorf("Parse(%q) error = %q, want hint containing %q", c.src, msg, frag)
			}
		}
	}
}

// TestParseShorthandEscaping — quoted shorthand values go through the
// same string-decoding path as the long form (escapes honored).
func TestParseShorthandEscaping(t *testing.T) {
	n := mustParse(t, `title:"a \"quoted\" word"`)
	cmp, ok := n.(*ast.Comparison)
	if !ok {
		t.Fatalf("want Comparison, got %T", n)
	}
	if cmp.Op != ast.OpEq {
		t.Errorf("op = %v, want ==", cmp.Op)
	}
	sv, ok := cmp.Value.(*ast.StrValue)
	if !ok {
		t.Fatalf("value type %T, want StrValue", cmp.Value)
	}
	if sv.S != `a "quoted" word` {
		t.Errorf("decoded value = %q, want %q", sv.S, `a "quoted" word`)
	}
}

// TestParseShorthandK13Limits — the shorthand consumes the same node
// budget as the long form.  Parentheses are syntax, not nodes (they
// collapse — pinned by TestParsePrecedence), so the depth limit trips on
// a NOT chain; the node-count limit trips on a wide OR chain.
func TestParseShorthandK13Limits(t *testing.T) {
	// 40 nested NOTs over a shorthand leaf — over maxDepth (32).
	deep := strings.Repeat("!", 40) + "port:443"
	pe := parseErr(t, deep)
	if !strings.Contains(pe.Detail, "nesting limit") {
		t.Errorf("deep shorthand: got %q, want the K-13 nesting-limit error", pe.Detail)
	}
	// A BALANCED binary OR tree of 1024 shorthand leaves — node count
	// 2047 > 1024 while the depth stays ~11 (a left-leaning chain would
	// trip the depth limit first; the balanced form isolates the count).
	var build func(lo, hi int) string
	build = func(lo, hi int) string {
		if hi-lo == 1 {
			return fmt.Sprintf("port%d:%d", (lo%9)+1, lo)
		}
		mid := (lo + hi) / 2
		return "(" + build(lo, mid) + " || " + build(mid, hi) + ")"
	}
	wide := build(0, 1024)
	pe = parseErr(t, wide)
	if !strings.Contains(pe.Detail, "node limit") {
		t.Errorf("wide shorthand: got %q, want the K-13 node-limit error", pe.Detail)
	}
}

// TestParseShorthandPosition — shorthand comparisons carry the FIELD's
// position (identical to the long form's node), so validator/planner
// error messages point at the user's input.
func TestParseShorthandPosition(t *testing.T) {
	n := mustParse(t, "port:443")
	cmp, ok := n.(*ast.Comparison)
	if !ok {
		t.Fatalf("want Comparison, got %T", n)
	}
	if cmp.Field != "port" {
		t.Errorf("field = %q", cmp.Field)
	}
	line, col := cmp.Pos()
	if line != 1 || col != 1 {
		t.Errorf("pos = %d:%d, want 1:1", line, col)
	}
}
