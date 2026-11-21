// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package gql contains the GSEER Query Language implementation:
// lexer → parser → ast → validator → planner (SPEC-04).
//
// M1: package skeleton only (this doc.go and the sub-package doc.go files).
// The execution order per the Phase 1 plan is M5 (lexer) → M8 (ast) →
// M6 (parser) → M7 (validator) → M9 (planner).  M1 lands the package
// layout per SPEC-02 §2 so the import-graph test (AC-3.1) can pin the
// absence of collector/egress dependencies from the very first commit.
//
// The gql package never imports any collector, egress, or P2 package
// (ADR-0010 Search ≠ Scan).
package gql
