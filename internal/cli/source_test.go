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
