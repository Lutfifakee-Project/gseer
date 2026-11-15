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

// status_test.go — subprocess acceptance for `gseer status` (the REAL
// binary, real exit codes, real shared-index channel): the honest
// fresh-machine states, the verified+installed reporting after an
// actual shared-index import, and the JSON view.
package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSubprocStatusFreshMachine(t *testing.T) {
	home := freshHome(t)
	out, code := runGseer(t, home, nil, "status")
	if code != 0 {
		t.Fatalf("status exited %d\noutput: %s", code, out)
	}
	for _, want := range []string{"not provisioned", "not installed"} {
		if !strings.Contains(out, want) {
			t.Fatalf("fresh-machine status output missing %q:\n%s", want, out)
		}
	}
	// JSON view: valid, with the honest null shared_index.
	outJSON, code := runGseer(t, home, nil, "status", "-o", "json")
	if code != 0 {
		t.Fatalf("status -o json exited %d\noutput: %s", code, outJSON)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(outJSON), &v); err != nil {
		t.Fatalf("status -o json is not valid JSON: %v\n%s", err, outJSON)
	}
	if got, ok := v["shared_index"]; !ok || got != nil {
		t.Fatalf("fresh-machine JSON shared_index must be null, got: %v", got)
	}
}

func TestSubprocStatusBadOutputFormatExit2(t *testing.T) {
	home := freshHome(t)
	out, code := runGseer(t, home, nil, "status", "-o", "xml")
	if code != 2 { // SPEC-03 §9: invalid input = exit 2
		t.Fatalf("status -o xml must exit 2, got %d\noutput: %s", code, out)
	}
	if !strings.Contains(out, "E_STATUS_OUTPUT") {
		t.Fatalf("status -o xml must name the refusal:\n%s", out)
	}
}

func TestSubprocStatusReportsVerifiedInstalled(t *testing.T) {
	ch := newIndexChannel(t, 1)
	home := freshHome(t)
	out, code := runGseer(t, home, map[string]string{"GSEER_INDEX_MANIFEST_URL": ch.manifestURL}, "setup")
	if code != 0 {
		t.Fatalf("setup exited %d\noutput: %s", code, out)
	}
	out, code = runGseer(t, home, nil, "status")
	if code != 0 {
		t.Fatalf("status exited %d\noutput: %s", code, out)
	}
	for _, want := range []string{
		"verified + installed sequence 1",
		"personal",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "imported into store: true") {
		t.Fatalf("status must report the imported state:\n%s", out)
	}
}
