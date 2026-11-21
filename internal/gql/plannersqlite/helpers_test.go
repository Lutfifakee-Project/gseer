// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package plannersqlite

// helpers_test.go — shared test helpers.

import (
	"errors"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/gql/validator"
)

func mustEncode(t *testing.T, c planner.CursorPayload) string {
	t.Helper()
	return c.Encode()
}

func asPlannerError(err error, target **planner.Error) bool {
	return errors.As(err, target)
}

// pgFreeTextList pins the free-text field list to the validator's
// exported list — the single source of truth both dialect planners
// mirror (the PG planner pins itself to the same list).
func pgFreeTextList(t *testing.T) []string {
	t.Helper()
	return validator.FreeTextFields
}
