// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// doctor_help_test.go — R4 targeted-followup regression tests (owner
// WSL acceptance finding #1): the `gseer doctor --help` long text
// still advertised the retired self-hosted surface ("PostgreSQL 16+",
// "runtime credential ... self-hosted", a `gseer db migrate` pointer
// whose command no longer exists).  The help text is a USER-VISIBLE
// surface — these tests pin it to the SQLite-only reality.  Doctor's
// RUNTIME output was already clean and must stay clean (second test),
// and a sweep over EVERY top-level command's help keeps the whole CLI
// surface honest (third test).
//
// These tests drive RootCmd directly, so they SNAPSHOT the exact
// pre-test state (writers, args, every flag value + Changed marker
// across the whole command tree) and restore it afterwards.  Restoring
// the snapshot — not defaults — is essential: other tests in this
// package set flags/args deliberately and call RunE directly; an
// over-eager default reset broke them (observed: TestVersionCommandOutput
// rendered help because a leaked --help Changed marker survived cobra's
// in-process flag state; TestExportPersonalStdout exited the test
// binary).

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// rootArgsSnapshot mirrors the RootCmd args observed at snapshot time;
// this file only ever sets ["<cmd>", "--help"] through setRootArgs.
var rootArgsSnapshot []string

func setRootArgs(args []string) {
	rootArgsSnapshot = args
	RootCmd.SetArgs(args)
}

// snapshotRootCmdState restores the writers/args state after tests
// that drive RootCmd directly.
//
// NOTE: no flag snapshot/restore.  helpFor renders help WITHOUT parsing
// flags, and the runtime doctor invocation sets no flags — this file
// changes no flag state at all.  Restoring SNAPSHOTTED values (the
// dirty state other tests deliberately leave behind, which their own
// cleanups re-establish) actively broke them.
func snapshotRootCmdState(t *testing.T) {
	t.Helper()
	args := rootArgsSnapshot
	t.Cleanup(func() {
		// Writers go back to the unset state on EVERY command: cobra
		// resolves output by inheritance from the parent, and restoring
		// an EFFECTIVE writer (OutOrStdout) as an EXPLICIT one would pin
		// a stale writer and make later tests' SetOut on the root
		// invisible to subcommands.  Unset == the tree's original state.
		var reset func(*cobra.Command)
		reset = func(c *cobra.Command) {
			c.SetOut(nil)
			c.SetErr(nil)
			for _, sub := range c.Commands() {
				reset(sub)
			}
		}
		reset(RootCmd)
		RootCmd.SetArgs(args)
	})
}

// helpFor renders one command's help WITHOUT executing the command:
// cobra parses flags (and keeps their Changed state) during Execute, and
// cross-test leakage of that in-process state poisoned later tests.  The
// command's own HelpFunc renders the exact same long/short text the CLI
// shows for `<cmd> --help`, into the command's own buffer — zero global
// state is touched.  (The text rendered IS the registered Long — the
// surface under audit.)
func helpFor(t *testing.T, name string) string {
	t.Helper()
	cmd, _, ferr := RootCmd.Find([]string{name})
	if ferr != nil {
		t.Fatalf("%s not registered: %v", name, ferr)
	}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	t.Cleanup(func() {
		cmd.SetOut(nil)
		cmd.SetErr(nil)
	})
	cmd.HelpFunc()(cmd, []string{name, "--help"})
	if !strings.Contains(buf.String(), "Usage:") {
		t.Fatalf("%s help capture failed (empty buffer)", name)
	}
	return buf.String()
}

// TestDoctorHelpIsSQLiteOnly — the doctor help must describe the ONE
// embedded SQLite database and must never resurrect the retired
// PostgreSQL/self-hosted surface or the retired `db migrate` pointer.
func TestDoctorHelpIsSQLiteOnly(t *testing.T) {
	snapshotRootCmdState(t)
	help := helpFor(t, "doctor")

	for _, banned := range []string{"PostgreSQL", "postgres", "PG version", "self-hosted", "runtime credential", "db migrate"} {
		if strings.Contains(help, banned) {
			t.Errorf("doctor --help still advertises the retired surface %q:\n%s", banned, help)
		}
	}
	if !strings.Contains(help, "SQLite") {
		t.Errorf("doctor --help must describe the embedded SQLite database:\n%s", help)
	}
}

// TestDoctorRuntimeOutputIsSQLiteOnly — doctor's PASS/FAIL runtime
// output never mentions PostgreSQL or self-hosted (it was already clean
// on the R4 candidate; this pins it so the help fix cannot drift the
// runtime).
func TestDoctorRuntimeOutputIsSQLiteOnly(t *testing.T) {
	withDatasetEnv(t)
	withConfigPath(t, "")
	buf := &bytes.Buffer{}
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	setRootArgs([]string{"doctor"})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("doctor: %v", err)
	}
	got := strings.ToLower(buf.String())
	for _, banned := range []string{"postgres", "pg version", "self-hosted", "runtime credential"} {
		if strings.Contains(got, banned) {
			t.Errorf("doctor runtime output mentions %q:\n%s", banned, buf.String())
		}
	}
}

// TestAllCommandHelpSQLiteOnly — sweep EVERY top-level command's help
// through the public route: the retired PostgreSQL/self-hosted surface
// may appear only as an explicit retirement note or an explicit "NO"
// negation (e.g. "There is NO … PostgreSQL, and NO Docker"); it must
// never be offered as an available mode or command.
func TestAllCommandHelpSQLiteOnly(t *testing.T) {
	snapshotRootCmdState(t)
	top := []string{"search", "setup", "doctor", "version", "status", "db", "dataset", "source", "collect", "scope", "scan", "export", "suppress", "update", "host"}
	for _, name := range top {
		help := strings.ToLower(helpFor(t, name))
		for _, line := range strings.Split(help, "\n") {
			if !strings.Contains(line, "postgres") && !strings.Contains(line, "self-hosted") {
				continue
			}
			// Allowed ONLY as a retirement note or an explicit negation
			// (including the multi-line continuation of "NO … PostgreSQL,
			// and NO Docker").
			if strings.Contains(line, "retired") || strings.Contains(line, "no postgres") ||
				strings.Contains(line, "old postgresql") || strings.Contains(line, "and no docker") {
				continue
			}
			t.Errorf("%s --help offers the retired surface outside a retirement note: %q", name, strings.TrimSpace(line))
		}
	}
}
