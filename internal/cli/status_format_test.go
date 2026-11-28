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

import (
	"bytes"
	"strings"
	"testing"
)

// TestRenderStatusTableVersionNoDoublePrefix locks the R06 fix: the
// status table prints the build version exactly as injected — never a
// doubled "v" prefix ("vv0.3.3-rc1" — the pre-fix bug), and never a
// fabricated prefix for the dev fallback ("gseer dev", consistent with
// `gseer version` and the banner's bannerVersion() convention).
func TestRenderStatusTableVersionNoDoublePrefix(t *testing.T) {
	const (
		commit = "d7f6ec2958c06eb94ddf6ccdc2b0a61d940da543"
		built  = "2026-11-28T06:38:08Z"
		sha    = "05c19f89c541d41fadd62457c54fc53d633fdd49f297300f2eff15b1635658c8"
	)
	cases := []struct {
		name    string
		version string
		want    string // exact binary line (without trailing newline)
		banned  []string
	}{
		{
			name:    "release candidate (ldflags injects v-prefixed tag)",
			version: "v0.3.3-rc1",
			want:    "  binary       : gseer v0.3.3-rc1 (commit " + commit + ", built " + built + ") sha256=" + sha,
			banned:  []string{"vv", "gseer vvv"},
		},
		{
			name:    "stable release tag",
			version: "v0.3.1",
			want:    "  binary       : gseer v0.3.1 (commit " + commit + ", built " + built + ") sha256=" + sha,
			banned:  []string{"vv"},
		},
		{
			name:    "dev fallback (un-injected build stays honest, no vdev/vvdev)",
			version: "dev",
			want:    "  binary       : gseer dev (commit " + commit + ", built " + built + ") sha256=" + sha,
			banned:  []string{"gseer vdev", "vvdev"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			renderStatusTable(&buf, statusView{
				Binary: statusBinary{
					Version: tc.version,
					Commit:  commit,
					BuiltAt: built,
					SHA256:  sha,
				},
			})
			var binaryLine string
			for _, l := range strings.Split(buf.String(), "\n") {
				if strings.HasPrefix(l, "  binary       : ") {
					binaryLine = l
					break
				}
			}
			if binaryLine == "" {
				t.Fatalf("no binary line in status table:\n%s", buf.String())
			}
			if binaryLine != tc.want {
				t.Errorf("status binary line =\n  %q\nwant\n  %q", binaryLine, tc.want)
			}
			for _, b := range tc.banned {
				if strings.Contains(binaryLine, b) {
					t.Errorf("status binary line contains banned fragment %q: %q", b, binaryLine)
				}
			}
		})
	}
}
