// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// first_run_test.go — the zero-configuration entry point (v0.3.0):
// bare `gseer` auto-initializes personal mode on the first run, prints
// an honest status afterwards, and `--version` finally works (the flag
// existed since M1 but was never consumed).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// firstRun executes the root command with the given args against an
// isolated home directory and returns the output.
func firstRun(t *testing.T, args ...string) string {
	t.Helper()
	return firstRunAt(t, t.TempDir(), args...)
}

func firstRunAt(t *testing.T, home string, args ...string) string {
	t.Helper()
	// Isolate the home directory: configDir() and the config loader
	// resolve the default paths through os.UserHomeDir().  The Rev16
	// default PERSONAL DATABASE path also honors XDG_STATE_HOME and
	// GSEER_HOME, so both are pinned empty — otherwise a test host with
	// either set would resolve the database outside the isolated HOME
	// (non-deterministic on machines with a real XDG state dir).
	t.Setenv("HOME", home)
	t.Setenv("GSEER_CONFIG", "")
	t.Setenv("GSEER_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	oldCfg, oldQuiet, oldProfile := flags.configPath, flags.quiet, flags.profile
	t.Cleanup(func() {
		flags.configPath, flags.quiet, flags.profile = oldCfg, oldQuiet, oldProfile
		RootCmd.SetArgs([]string{})
		RootCmd.SetOut(nil)
		RootCmd.SetErr(nil)
	})
	flags.configPath, flags.quiet, flags.profile = "", false, ""

	var buf bytes.Buffer
	RootCmd.SetOut(&buf)
	RootCmd.SetErr(&buf)
	// Bare invocation MUST pass an EMPTY (non-nil) slice: SetArgs(nil)
	// makes cobra fall back to os.Args — the test binary's own flags.
	if args == nil {
		args = []string{}
	}
	RootCmd.SetArgs(args)
	// pflag values PERSIST across Execute calls on the shared command
	// tree: a previous test's parsed `--help` would force this bare run
	// into cobra's help path instead of RunE.  Reset it explicitly.
	_ = RootCmd.Flags().Set("help", "false")
	t.Logf("diag: RunE set=%v args=%q", RootCmd.RunE != nil, args)
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("execute %v: %v\noutput: %s", args, err, buf.String())
	}
	return buf.String()
}

func TestFirstRunAutoInitializesPersonalMode(t *testing.T) {
	home := t.TempDir()
	out := firstRunAt(t, home)

	for _, want := range []string{
		"Welcome to GSEER",
		"personal database",
		"migrations: schema at head",
		"config written",
		"Where does the data come from?",
		"gseer setup --load-fixtures",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("first-run output missing %q:\n%s", want, out)
		}
	}
	// The artifacts exist at the platform paths under the isolated HOME.
	// Rev16 portability contract: the CONFIG stays at ~/.gseer, while the
	// personal DATABASE defaults to the persistent XDG state directory
	// ($HOME/.local/state/gseer — the XDG_STATE_HOME fallback), never the
	// config dir and never a /tmp-derived path.
	if _, err := os.Stat(filepath.Join(home, ".gseer", "config.yaml")); err != nil {
		t.Errorf("config.yaml not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "state", "gseer", "gseer.db")); err != nil {
		t.Errorf("personal database not created in the XDG state dir: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(home, ".gseer", "gseer.db")); serr == nil {
		t.Errorf("the database must NOT live in the config dir anymore (pre-Rev16 layout)")
	}
	if !strings.Contains(out, filepath.Join("state", "gseer", "gseer.db")) &&
		!strings.Contains(out, string(filepath.Separator)+"state"+string(filepath.Separator)) {
		t.Errorf("first-run output must name the state-dir database path, got:\n%s", out)
	}

	// A second bare run is the STATUS panel — no re-initialization.
	out2 := firstRunAt(t, home)
	if strings.Contains(out2, "Welcome to GSEER") {
		t.Errorf("second run re-initialized (must be the status panel):\n%s", out2)
	}
	for _, want := range []string{"profile: personal", "index:", "EMPTY"} {
		if !strings.Contains(out2, want) {
			t.Errorf("status output missing %q:\n%s", want, out2)
		}
	}
}

func TestFirstRunVersionFlagConsumed(t *testing.T) {
	out := firstRun(t, "--version")
	if !strings.Contains(out, "gseer ") {
		t.Errorf("--version output missing the version block:\n%s", out)
	}
	if strings.Contains(out, "Welcome") || strings.Contains(out, "profile:") {
		t.Errorf("--version must not run the first-run/status flow:\n%s", out)
	}
}

// TestZeroConfigAppliesInsideGSEERHome pins the v0.3.2 write/read
// symmetry fix: a GSEER_HOME install with NO config inside it still
// counts as zero-config fresh (the old blanket GSEER_HOME exclusion made
// bare `gseer setup` fail with the misleading client-profile
// E_CONFIG_REQUIRED instead of provisioning personal mode), while a
// config INSIDE GSEER_HOME keeps the later-runs status path.
func TestZeroConfigAppliesInsideGSEERHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	gh := t.TempDir()
	t.Setenv("GSEER_HOME", gh)

	if !zeroConfigFirstRunApplies() {
		t.Fatal("an empty GSEER_HOME must count as zero-config fresh")
	}
	if err := os.MkdirAll(gh, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gh, "config.yaml"), []byte("profile: personal\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if zeroConfigFirstRunApplies() {
		t.Fatal("a config inside GSEER_HOME must disable the zero-config path")
	}
}
