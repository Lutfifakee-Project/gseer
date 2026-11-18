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

// ci_state_hygiene_test.go — regression tests for the two post-push CI
// failures (the PostgreSQL 16/17 integration job), both rooted in the
// shared state of the singleton cobra command tree:
//
//  1. `sourceAddReset` zeroed the shared flag struct; pflag never
//     re-applies registered defaults, so the next `source add` that
//     omitted --seed-mode saw seed_mode "" — outside the accepted
//     config|index|none contract — and failed with E_USAGE.  The seam
//     now restores the REGISTERED defaults; these tests pin the
//     contract so it cannot regress.
//  2. Tests that SetOut a private buffer directly on a SUBcommand
//     (dataset update, search, ...) poisoned the shared tree: cobra's
//     OutOrStdout prefers a command's own writer over the inherited
//     one, so later executeRoot-driven invocations captured an EMPTY
//     output with a nil error (the "CLI output empty" facets E2E
//     failure).  executeRoot now clears child writers first; this test
//     pins that immunity.

import (
	"bytes"
	"strings"
	"testing"
)

// TestSourceAddResetRestoresRegisteredDefaults — after sticky values of
// exactly the kind earlier tests leave behind (an invalid seed-mode among
// them), the reset seam must bring EVERY flag back to its registered
// default — not to a zero value.
func TestSourceAddResetRestoresRegisteredDefaults(t *testing.T) {
	add, _, err := RootCmd.Find([]string{"source", "add"})
	if err != nil {
		t.Fatal(err)
	}
	for _, sticky := range []struct{ flag, value string }{
		{"seed-mode", "wordlist"}, {"seeds", "a.example,b.example"},
		{"seed-kind", "domain"}, {"type", "dns"}, {"enable", "true"},
		{"yes", "true"}, {"limit-per-run", "42"},
		{"endpoint", "https://example.invalid/"},
	} {
		if err := add.Flags().Set(sticky.flag, sticky.value); err != nil {
			t.Fatalf("set --%s: %v", sticky.flag, err)
		}
	}
	sourceAddReset()
	for _, want := range []struct{ flag, def string }{
		{"seed-mode", "config"}, {"seed-kind", "ip"}, {"type", ""},
		{"endpoint", ""}, {"limit-per-run", "0"},
	} {
		fl := add.Flags().Lookup(want.flag)
		if fl == nil {
			t.Fatalf("flag %q missing", want.flag)
		}
		if fl.Value.String() != want.def {
			t.Errorf("--%s = %q after reset, want the registered default %q",
				want.flag, fl.Value.String(), want.def)
		}
		if fl.Changed {
			t.Errorf("--%s still marked Changed after reset", want.flag)
		}
	}
	if seeds := add.Flags().Lookup("seeds"); seeds.Value.String() != "[]" || seeds.Changed {
		t.Errorf("--seeds not reset to the empty default: %q (Changed=%v)",
			seeds.Value.String(), seeds.Changed)
	}
	if en := add.Flags().Lookup("enable"); en.Value.String() != "false" {
		t.Errorf("--enable not reset to false: %q", en.Value.String())
	}
}

// TestSourceAddSeedModeContract — the implementation accepts exactly
// config, index or none; validation must accept all three (the run then
// fails offline for other reasons, never with an E_USAGE seed-mode
// refusal), and OMITTING the flag must behave exactly like
// --seed-mode config.
func TestSourceAddSeedModeContract(t *testing.T) {
	withDatasetEnv(t)         // a fresh temp home: no personal store touched or created
	t.Cleanup(sourceAddReset) // leave the shared source-add flags pristine
	for _, mode := range []string{"config", "index", "none"} {
		args := []string{"source", "add", "x", "--type", "dns", "--seed-mode", mode}
		if mode == "config" {
			args = append(args, "--seeds", "a.example")
		}
		_, err := runCLI(t, args...)
		if err != nil && strings.Contains(err.Error(), "E_USAGE") {
			t.Errorf("seed-mode %q must be accepted by validation, got: %v", mode, err)
		}
	}
	// With the struct-zeroing seam this got the WRONG refusal
	// ("--seed-mode must be config, index or none") because the omitted
	// flag inherited "" instead of the registered default.
	_, err := runCLI(t, "source", "add", "x", "--type", "dns")
	if err == nil || !strings.Contains(err.Error(), "--seed-mode config needs --seeds") {
		t.Fatalf("omitted --seed-mode must default to config (contract refusal), got: %v", err)
	}
}

// TestExecuteRootCapturesOutputDespiteChildWriterLeak — a subcommand whose
// output writer was left pinned by an earlier test must not swallow the
// output of a later executeRoot invocation.
func TestExecuteRootCapturesOutputDespiteChildWriterLeak(t *testing.T) {
	searchCmd, _, err := RootCmd.Find([]string{"search"})
	if err != nil {
		t.Fatal(err)
	}
	stale := &bytes.Buffer{}
	searchCmd.SetOut(stale) // the exact leak class the dataset tests had
	t.Cleanup(func() { searchCmd.SetOut(nil) })
	// --validate is as sticky as any other search flag on the shared tree:
	// reset it so later direct-RunE invocations search instead of merely
	// validating (the same discipline every search-using test applies).
	t.Cleanup(searchFlagsReset)
	out, err := executeRoot(t, "search", "--validate", `port == 443`)
	if err != nil {
		t.Fatalf("search --validate: %v\nout: %s", err, out)
	}
	if !strings.Contains(out, "valid GQL") {
		t.Fatalf("executeRoot captured no command output (a stale child writer swallowed it):\n%q", out)
	}
}
