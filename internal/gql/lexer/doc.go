// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package lexer is the GQL token stream producer (SPEC-04 §2–3).
//
// M5 (landed): the table-driven lexer.  Every token carries a 1-based
// line:col (columns count runes); string literals decode the
// \" \\ \/ \b \f \n \r \t and \uXXXX escapes; integer literals are
// digit runs; identifiers are dot-paths; AND/OR/NOT and the operator
// keywords IN/ANY/ALL/CONTAINS/IN_CIDR/IN_DOMAIN match
// case-insensitively as their own token kinds (the parser, M6, applies
// the keyword→symbol sugar).  Quantified-block braces { } tokenize as
// punctuation (the M8 canonical form ANY(f){ … } re-lexes — the parser
// decides where they are legal).  Lexical failures abort with GQL_E_LEX
// at the exact position plus a concrete "Try:" hint (errors.go),
// following the project-wide error rendering.  See lexer.go's
// file-policy comment for the deliberate M5 boundaries (maximal munch,
// `=` sugar token, no bare negative numbers, true/false stay
// identifiers).
//
// Consumed by the M6 recursive-descent parser; never imports any
// collector, egress, or P2 package (ADR-0010; AC-3.1).
package lexer
