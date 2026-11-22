// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"os"
	"testing"
)

// exitFuncGuard replaces the process-exit seam for the duration of one
// test (the shared RootCmd leaks persistent cobra flags between tests —
// see search.go's searchFlagsReset comment — so an in-process RunE that
// calls exitWith would otherwise os.Exit the whole test binary).
// Restored via t.Cleanup; a recorded exit fails the test with context.
func exitFuncGuard(t *testing.T) *int {
	t.Helper()
	called := new(int)
	orig := exitFunc
	exitFunc = func(code int) {
		*called = code
		t.Errorf("exitWith(%d) called in-process — an exit-code path leaked into the test binary", code)
	}
	t.Cleanup(func() { exitFunc = orig })
	return called
}

// shorthand_e2e_test.go — the five OWNER acceptance queries
// (docs/audit/V032-SEARCH-SYNTAX-AUDIT.md §1 R1) run against the REAL
// central dataset v1 through the REAL signed import journey, with EXACT
// counts.  The shorthand queries assert the same counts as their
// documented long forms on the same corpus (equivalence on real data),
// and the apache/nginx free-text zeros are HONEST dataset-coverage
// facts (v1 carries no Apache/Nginx product rows — see the corpus note
// in TestCentralDatasetV1RealEvidenceE2E), never silent filters.
func TestCentralDatasetV1ShorthandOwnerTargetsE2E(t *testing.T) {
	withDatasetEnv(t)
	resetSetupFlags(t)
	exits := exitFuncGuard(t)

	manifestURL, _ := serveCentralV1(t)
	t.Setenv("GSEER_DATASET_MANIFEST_URL", manifestURL)

	if _, err := runCLI(t, "setup", "--personal"); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}
	// --manifest-url explicitly: the shared update command's flag is
	// persistent across Execute() calls (the documented cobra pitfall),
	// and an earlier suite test may have left a dead URL there.
	if _, err := runCLI(t, "dataset", "update", "--manifest-url", manifestURL); err != nil {
		t.Fatalf("dataset update: %v", err)
	}
	if *exits != 0 {
		t.Fatalf("the update journey called exitWith(%d) — exit code leaked into the test binary", *exits)
	}

	targets := []struct {
		query string
		want  int
		note  string
	}{
		// bare word = free text; v1 has no Apache rows → honest 0
		{"apache", 0, "free text; dataset v1 has no apache rows (honest zero)"},
		// shorthand AND free text: port:443 alone = 15; with apache → 0 (honest)
		{"port:443 && apache", 0, "shorthand + free text; the apache term has no rows"},
		// free-text OR: no apache/nginx rows → honest 0
		{"apache || nginx", 0, "free-text OR; dataset v1 has no apache/nginx rows"},
		// parens + shorthand, counts equal to the documented long forms
		{"(apache || nginx) && country:ID", 0, "parens + shorthand + free text; honest zero"},
		{"(port:80 || port:443) && country:ID", 0, "shorthand OR + shorthand; country:ID has 0 rows in v1 (honest)"},
		// the same acceptance SHAPES with values the corpus actually
		// carries — each equals its long-form count pinned in
		// TestCentralDatasetV1RealEvidenceE2E
		{"port:443", 15, "== port=443"},
		{"port:443 && protocol:https", 15, "== port=443 && protocol=\"https\""},
		{"country:US", 47, "== country=\"US\""},
		{"asn:13335", 20, "== asn=\"13335\""},
		{"(port:80 || port:443) && country:US", 12, "== (port=80 || port=443) && country=\"US\""},
		{"country:US || country:DE", 47, "shorthand OR; only US rows exist in v1 (honest)"},
		// free-text machinery on real data (the term that exists)
		{"\"cloudflare\"", 28, "quoted free text (documented evidence row)"},
	}
	for _, tc := range targets {
		if got := countRows(t, tc.query); got != tc.want {
			t.Errorf("owner target %q = %d rows, want %d (%s)", tc.query, got, tc.want, tc.note)
		}
	}
}

// TestSeedE2EHomeForBinary — seeds a FIXED home path through the REAL
// signed update journey so the delivered `gseer` BINARY can run the
// owner acceptance queries against real data (the binary-level search
// path is the production path; the import's trust anchor is the
// documented test seam because the production signing seed is
// owner-only by design).  Gated by GSEER_E2E_SEED_HOME — skipped in
// normal `go test ./...` runs.
func TestSeedE2EHomeForBinary(t *testing.T) {
	home := os.Getenv("GSEER_E2E_SEED_HOME")
	if home == "" {
		t.Skip("GSEER_E2E_SEED_HOME not set — binary-level E2E seeding not requested")
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("GSEER_HOME", home)
	resetSetupFlags(t)
	exitFuncGuard(t)

	manifestURL, _ := serveCentralV1(t)
	t.Setenv("GSEER_DATASET_MANIFEST_URL", manifestURL)

	if _, err := runCLI(t, "setup", "--personal"); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}
	if _, err := runCLI(t, "dataset", "update", "--manifest-url", manifestURL); err != nil {
		t.Fatalf("dataset update: %v", err)
	}
}
