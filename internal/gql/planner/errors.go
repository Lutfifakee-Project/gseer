// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package planner

import (
	"strings"
)

// errors.go — the planner error type (SPEC-03 §7 style guide).
//
// Planner failures carry one of the stable GQL_E_PLAN_* codes below.
// They surface problems the validator could not catch (unknown sort
// field, malformed cursor, mode/sort incompatibility) and never overlap
// with the M7 validator's GQL_E_* semantic codes.

// Stable planner error codes.
const (
	// CodePlanEmpty is returned when Compile is called with a nil root.
	CodePlanEmpty = "GQL_E_PLAN_EMPTY"

	// CodePlanSortField is returned when the requested sort field is not
	// in the sortable registry (or is a list/bool field, which cannot
	// sort meaningfully).
	CodePlanSortField = "GQL_E_PLAN_SORT_FIELD"

	// CodePlanSortDir is returned when the sort direction is not one of
	// "asc" / "desc" (case-insensitive).
	CodePlanSortDir = "GQL_E_PLAN_SORT_DIR"

	// CodePlanCursor is returned when the cursor cannot be decoded or
	// does not match the current sort field/direction.
	CodePlanCursor = "GQL_E_PLAN_CURSOR"

	// CodePlanLimit is returned when the requested limit is out of range.
	CodePlanLimit = "GQL_E_PLAN_LIMIT"

	// CodePlanTimeout is returned when the requested timeout is out of
	// range (must be > 0 and <= the 30s hard cap, PD-1).
	CodePlanTimeout = "GQL_E_PLAN_TIMEOUT"

	// CodePlanMode is returned when the mode is not ModeService or
	// ModeAsset.
	CodePlanMode = "GQL_E_PLAN_MODE"

	// CodePlanProjection is returned when a requested projection field
	// is not a known search_index column.
	CodePlanProjection = "GQL_E_PLAN_PROJECTION"
)

// Error is a planner error.
type Error struct {
	Code   string
	Detail string
	Why    string
	Next   string
}

// Error renders per the SPEC-03 §7 style guide.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Code + ": " + e.Detail)
	if e.Why != "" {
		b.WriteString("\nWhy: " + e.Why)
	}
	if e.Next != "" {
		b.WriteString("\nTry: " + e.Next)
	}
	return b.String()
}
