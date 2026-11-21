// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// source_test.go — regression: `source add --seeds` must accept BOTH the
// comma-separated form (humans) and the whitespace-separated single
// argument form (the CI pipeline passes `shlex.join` output).  Before
// Rev 11 a space-separated list was stored as ONE seed string and the
// DNS connector queried a nonsense "domain" — found by the Rev 11
// workflow dry-run.
import (
	"reflect"
	"testing"
)

func TestNormalizeSeedArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "comma separated (single arg)",
			in:   []string{"example.net,example.org"},
			want: []string{"example.net", "example.org"},
		},
		{
			name: "space separated (single arg — the CI form)",
			in:   []string{"example.net example.org dns.google"},
			want: []string{"example.net", "example.org", "dns.google"},
		},
		{
			name: "mixed commas, spaces, repeated args, duplicates",
			in:   []string{"example.net, example.org", "example.org\tdns.google", "kernel.org"},
			want: []string{"example.net", "example.org", "dns.google", "kernel.org"},
		},
		{
			name: "only separators collapses to empty (usage error surface)",
			in:   []string{" , ,"},
			want: []string{},
		},
		{
			name: "nil input",
			in:   nil,
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeSeedArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeSeedArgs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
