// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package search implements the SearchService: validate → plan → execute
// → shape, applying the mode filter (default: service, PD-1) with no mode
// semantics in any caller (RS-3, SPEC-04).
//
// M1: package skeleton only (this doc.go).  Full implementation lands in
// M10.  The SearchService depends only on the read-side SearchIndex
// interface; it has no dependency on any collector, egress, or P2
// package (ADR-0010 Search ≠ Scan; AC-3.1 import-graph test).
package search
