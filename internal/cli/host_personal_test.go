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

// host_personal_test.go — the personal-mode `gseer host` report (the
// v0.3.2 wiring): provenance, timestamps, sources, and services surface
// through the embedded SQLite store with the same shape the self-hosted
// path prints.  The fixture corpus (RFC 5737 data) provides the asset,
// its 443/login service, and the fixture-source observations.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHostPersonalModeReport(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "gseer.db")
	withConfigPath(t, writePersonalConfigForTest(t, live))

	// The IP asset carries the fixture's services (443/https with the
	// login title); the domain asset is the passive-facts case (no
	// service rows — the report states that honestly).
	host, _, err := RootCmd.Find([]string{"host", "203.0.113.10"})
	if err != nil {
		t.Fatalf("host command not registered: %v", err)
	}
	out := &bytes.Buffer{}
	host.SetOut(out)
	if err := host.RunE(host, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("personal host: %v\n%s", err, out)
	}
	text := out.String()
	for _, want := range []string{
		"HOST 203.0.113.10",
		"sources:",
		"first_seen:",
		"last_seen:",
		"OBSERVATIONS:", // the provenance breakdown
		"443/tcp",       // the fixture's 443 service with its latest state
	} {
		if !strings.Contains(text, want) {
			t.Errorf("personal host output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "E_PROFILE_UNSUPPORTED") {
		t.Errorf("personal host must be wired, not refused:\n%s", text)
	}

	// The domain asset: the same report, honestly without service rows.
	out.Reset()
	if err := host.RunE(host, []string{"portal.example.net"}); err != nil {
		t.Fatalf("personal host (domain): %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "HOST portal.example.net") ||
		!strings.Contains(out.String(), "(none") {
		t.Errorf("domain host report unexpected:\n%s", out.String())
	}

	// The JSON form carries the same fields machine-readably.
	oldOut := flags.output
	flags.output = "json"
	t.Cleanup(func() { flags.output = oldOut })
	out.Reset()
	if err := host.RunE(host, []string{"203.0.113.10"}); err != nil {
		t.Fatalf("personal host (json): %v\n%s", err, out)
	}
	var rep hostReport
	if jerr := json.Unmarshal(out.Bytes(), &rep); jerr != nil {
		t.Fatalf("host json: %v\n%s", jerr, out)
	}
	if rep.Asset.Value != "203.0.113.10" {
		t.Errorf("json asset value = %q", rep.Asset.Value)
	}
	if rep.Asset.FirstSeen.IsZero() || rep.Asset.LastSeen.IsZero() {
		t.Errorf("json asset timestamps must be set: first=%v last=%v", rep.Asset.FirstSeen, rep.Asset.LastSeen)
	}
	if len(rep.Asset.Sources) == 0 {
		t.Errorf("json asset sources empty")
	}
	if rep.Observations.Total < 1 || len(rep.Observations.BySource) == 0 {
		t.Errorf("json provenance breakdown missing: %+v", rep.Observations)
	}
	if len(rep.Services) == 0 {
		t.Errorf("json services missing — the fixture's 443 service must surface")
	}

	// An unknown identifier is an honest no-match (no error, no exit).
	out.Reset()
	if err := host.RunE(host, []string{"does-not-exist.invalid"}); err != nil {
		t.Fatalf("unknown identifier must not error: %v\n%s", err, out)
	}
	if !strings.Contains(out.String(), "No asset matches") {
		t.Errorf("unknown identifier output:\n%s", out.String())
	}
}
