// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import "testing"

// TestSearchFlagsResetSeam pins the searchFlagsReset test seam in the
// untagged build: the seam is a no-op closure in production (cobra flag
// values persist on the shared RootCmd by design) and is swapped for a
// real reset by the integration-tagged suites, which must clear sticky
// --facet/--max-values values between Execute calls.  Calling it here
// keeps the seam referenced outside the integration build tag so the
// linter sees the intended use, and fails if the wiring regresses.
func TestSearchFlagsResetSeam(t *testing.T) {
	if searchFlagsReset == nil {
		t.Fatal("searchFlagsReset seam is nil; the cli integration suites would inherit sticky search flags")
	}
	searchFlagsReset() // must be safe to call at any time (no-op by default)
}
