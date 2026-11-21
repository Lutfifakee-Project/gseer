// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package version

import (
	"strings"
	"testing"
)

// TestCurrentDefaults verifies that an un-injected binary still reports
// honest values rather than blanks.  When ldflags are absent (e.g. `go
// test`), Version="dev", Commit/BuiltAt become "unknown", and GoVersion
// is the runtime's own version string.  This pins the honesty floor
// (AC-8.x): the version surface never lies about provenance.
func TestCurrentDefaults(t *testing.T) {
	info := Current()

	if info.Version != "dev" {
		t.Errorf("Version: want 'dev' (un-injected), got %q", info.Version)
	}
	if info.Commit != "unknown" {
		t.Errorf("Commit: want 'unknown' (un-injected), got %q", info.Commit)
	}
	if info.BuiltAt != "unknown" {
		t.Errorf("BuiltAt: want 'unknown' (un-injected), got %q", info.BuiltAt)
	}
	if !strings.HasPrefix(info.GoVersion, "go1.") {
		t.Errorf("GoVersion: want prefix 'go1.', got %q", info.GoVersion)
	}
}

// TestStringStable verifies the human-readable form contains every field
// and never collapses to empty.  The QUICKSTART (M11) pins the exact
// wording; this test pins the shape so future fields appear on their
// own line.
func TestStringStable(t *testing.T) {
	s := Current().String()

	for _, want := range []string{"gseer ", "commit:", "built_at:", "go:"} {
		if !strings.Contains(s, want) {
			t.Errorf("String(): missing %q in\n%s", want, s)
		}
	}
	for _, blank := range []string{"commit:   \n", "built_at: \n", "go:       \n"} {
		if strings.Contains(s, blank) {
			t.Errorf("String(): field collapsed to blank: %q", blank)
		}
	}
}
