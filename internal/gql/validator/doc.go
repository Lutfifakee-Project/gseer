// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package validator is the GQL semantic validator (SPEC-04 §5, §7).
//
// M7 (landed): the field registry derived from the search_index union
// view (migration 0003) with dotted canonical paths and user-facing
// aliases (title→http.title, country→geo_country, status→http.status,
// server→http.server, tech→technologies, …), alias rewrite to canonical
// paths in place, strict typing (port=="443" → GQL_E_TYPE with the
// unquoted rewrite; timestamps RFC 3339; booleans "true"/"false";
// IN lists type-check element-wise), operator/field compatibility via
// ast.OpSet (IN_CIDR only on ip, CONTAINS on text/list fields, range
// ops on ordered fields), quantifier scope validation (host|service),
// and the v0.0.1 feature gate: ALL(...) → GQL_E_NOT_SUPPORTED_IN_VERSION
// with the ANY rewrite suggestion.  Unknown fields fail with GQL_E_FIELD
// and a did-you-mean hint over the registry names (edit distance < 3).
//
// The registry table in validator.go is the single reconciliation point
// if SPEC-04 §7's normative field list differs from the in-repo
// derivation.
//
// Consumes internal/gql/ast; the planner (M9) consumes the validated,
// canonically-rewritten tree.  Never imports any collector or egress
// package (ADR-0010; AC-3.1).
package validator
