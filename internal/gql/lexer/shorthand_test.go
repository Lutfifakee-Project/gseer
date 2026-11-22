// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package lexer

import (
	"strings"
	"testing"
)

// shorthand_test.go — the v0.3.2 COLON token (FOFA-style shorthand
// `field:value`; docs/audit/V032-SEARCH-SYNTAX-AUDIT.md §3/§5).  The
// lexer only tokenizes; the parser decides where ':' is legal.

// TestLexColonShorthand — `field:value` lexes to IDENT COLON INT/STRING/
// IDENT without disturbing any other token shape.
func TestLexColonShorthand(t *testing.T) {
	toks, err := Lex("port:443")
	if err != nil {
		t.Fatalf("Lex(port:443): %v", err)
	}
	wantKinds := []Kind{IDENT, COLON, INT, EOF}
	wantTexts := []string{"port", ":", "443", ""}
	for i, tok := range toks {
		if tok.Kind != wantKinds[i] || tok.Text != wantTexts[i] {
			t.Errorf("token %d = %s, want %s(%q)", i, tok, wantKinds[i], wantTexts[i])
		}
	}
	// Quoted and bare-word values.
	toks, err = Lex(`country:"ID"`)
	if err != nil {
		t.Fatalf(`Lex(country:"ID"): %v`, err)
	}
	if toks[2].Kind != STRING || toks[2].Value != "ID" {
		t.Errorf("quoted shorthand value = %s (Value %q)", toks[2], toks[2].Value)
	}
	toks, err = Lex("country:ID")
	if err != nil {
		t.Fatalf("Lex(country:ID): %v", err)
	}
	if toks[2].Kind != IDENT || toks[2].Text != "ID" {
		t.Errorf("bare shorthand value = %s", toks[2])
	}
}

// TestLexColonKindName — the COLON kind renders for diagnostics.
func TestLexColonKindName(t *testing.T) {
	if COLON.String() != "COLON" {
		t.Errorf("COLON.String() = %q", COLON.String())
	}
}

// TestLexStrayColonHint — a ':' the parser will reject still lexes as
// COLON (legal character); the lexical hint for illegal-char errors no
// longer covers ':' — but the previously-illegal error path for other
// characters is untouched.  A stray colon now surfaces at the PARSER
// (GQL_E_PARSE) with the shorthand hint, so only the tokenizer shape is
// pinned here.
func TestLexStrayColonHint(t *testing.T) {
	toks, err := Lex("443:80")
	if err != nil {
		t.Fatalf("Lex(443:80): %v", err)
	}
	if toks[1].Kind != COLON {
		t.Errorf("token 1 = %s, want COLON", toks[1])
	}
}

// TestLexIllegalCharHintsUnchanged — the pre-shorthand illegal-character
// hints keep their text (backward compatibility of error messages).
func TestLexIllegalCharHintsUnchanged(t *testing.T) {
	_, err := Lex("a == 'x'")
	if err == nil {
		t.Fatalf("single quote must stay a lexical error")
	}
	if !strings.Contains(err.Error(), "double quotes") {
		t.Errorf("single-quote hint changed: %v", err)
	}
}
