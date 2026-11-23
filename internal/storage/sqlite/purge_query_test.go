// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

import (
	"strings"
	"testing"
)

// Guards for the fixture-purge query builders (R12 lint remediation).
// The builders keep every SQL fragment as a constant and take ONLY the
// placeholder count n; these tests pin the invariant that no id, source
// name or other data can ever reach the statement text.

// TestIntPlaceholdersSyntax: intPlaceholders must render exactly
// "?,?,…" — punctuation-only, for every n.
func TestIntPlaceholdersSyntax(t *testing.T) {
	for n := 0; n <= 2000; n++ {
		want := strings.TrimSuffix(strings.Repeat("?,", n), ",")
		if got := intPlaceholders(n); got != want {
			t.Fatalf("intPlaceholders(%d) = %q, want %q", n, got, want)
		}
	}
	for _, c := range intPlaceholders(500) {
		if c != '?' && c != ',' {
			t.Fatalf("unexpected character %q in placeholder list", c)
		}
	}
}

// TestPurgeQueryBuildersVaryOnlyInPlaceholders: for each builder the
// output for different n differs ONLY in the IN-clause placeholder list
// — everything else is byte-identical — and the number of bind
// placeholders is exactly n plus the builder's fixed ones.
func TestPurgeQueryBuildersVaryOnlyInPlaceholders(t *testing.T) {
	builders := []struct {
		name   string
		build  func(int) string
		fixedQ int // bind placeholders outside the IN list
	}{
		{"qFixtureAssetsOfServices", qFixtureAssetsOfServices, 0},
		{"qCountOrphanedServices", qCountOrphanedServices, 0},
		{"qDeleteOrphanedServices", qDeleteOrphanedServices, 0},
		{"qCountDetachedAssets", qCountDetachedAssets, 1},
		{"qDeleteDetachedAssets", qDeleteDetachedAssets, 1},
		{"qSelectTaggedAssets", qSelectTaggedAssets, 1},
	}
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			var normalized string
			for _, n := range []int{1, 2, 7, 99, 500} {
				q := b.build(n)
				if got := strings.Count(q, "?"); got != n+b.fixedQ {
					t.Fatalf("%s(%d): %d bind placeholders, want %d", b.name, n, got, n+b.fixedQ)
				}
				// Normalization needs a UNIQUE marker: a one-placeholder IN
				// list ("?") is not distinguishable from the builder's fixed
				// bind placeholders, so the byte-identity check starts at n=2.
				// The count check above already covers n=1.
				if n < 2 {
					continue
				}
				ph := intPlaceholders(n)
				if strings.Count(q, ph) != 1 {
					t.Fatalf("%s(%d): IN-list placeholder %q appears %d times, want 1", b.name, n, ph, strings.Count(q, ph))
				}
				norm := strings.Replace(q, ph, "@@", 1)
				if normalized == "" {
					normalized = norm
				} else if norm != normalized {
					t.Fatalf("%s: the non-placeholder part must be constant across n\ngot:  %q\nwant: %q", b.name, norm, normalized)
				}
			}
		})
	}
}
