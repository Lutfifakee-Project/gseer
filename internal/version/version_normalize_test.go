// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package version

// version_normalize_test.go — Rev16 regression tests for the version
// prefix normalization.  The owner-acceptance finding: a GoReleaser
// snapshot build injects a version string that already carries the "v"
// (snapshot version template), the banner de-duplicated it locally while
// `gseer version` / status / doctor echoed the raw value, so the same
// binary printed "v0.3.1-snapshot" and "vv0.3.1-snapshot" on different
// surfaces.  Current() now normalizes at ONE choke point; these tests
// pin the full input matrix and the cross-surface consistency.

import (
	"strings"
	"testing"
)

func TestNormalizeVersionMatrix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"dev", "dev"},                          // the honest no-metadata label — never "vdev"
		{"   dev  ", "dev"},                     // trimmed
		{"vv0.3.1-snapshot", "v0.3.1-snapshot"}, // doubled prefix collapsed (the finding)
		{"vvv0.3.1", "v0.3.1"},                  // arbitrarily doubled
		{"v0.3.1", "v0.3.1"},                    // already canonical — untouched
		{"0.3.1", "v0.3.1"},                     // un-prefixed release string → prefixed once
		{"0.3.1-snapshot", "v0.3.1-snapshot"},   // un-prefixed snapshot
		{"candidate", "candidate"},              // not version-shaped — untouched
		{"version", "version"},                  // a word, not a semver — untouched
		{"vvv", "vvv"},                          // all "v"s: nothing to prefix sensibly
	}
	for _, c := range cases {
		if got := normalizeVersion(c.in); got != c.want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCurrentNormalizesDoubledInjection pins the choke point: whatever
// the build injected (here, a doubled "vv…" as a GoReleaser snapshot
// build would produce), Current() reports exactly one canonical form so
// EVERY surface agrees.
func TestCurrentNormalizesDoubledInjection(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "vv0.3.1-snapshot"

	info := Current()
	if info.Version != "v0.3.1-snapshot" {
		t.Errorf("Current().Version = %q, want %q (normalized once)", info.Version, "v0.3.1-snapshot")
	}
	if strings.Contains(info.Version, "vv") {
		t.Errorf("Current().Version contains a doubled prefix: %q", info.Version)
	}
	if s := info.String(); !strings.Contains(s, "gseer v0.3.1-snapshot") {
		t.Errorf("Info.String() must render the normalized form, got:\n%s", s)
	}
}

// TestCurrentDevStaysDev guards the honesty floor against an over-eager
// normalizer: the no-metadata label must never gain a "v" prefix.
func TestCurrentDevStaysDev(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })
	Version = "dev"
	if got := Current().Version; got != "dev" {
		t.Errorf("Current().Version = %q, want %q", got, "dev")
	}
}
