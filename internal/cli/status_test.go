// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// status_test.go — subprocess acceptance for `gseer status` (the REAL
// binary, real exit codes): the honest fresh-machine states, the Local
// Index discovery section after a plain personal setup, and the JSON
// view.  v0.3.2 CLI-only architecture: the shared-index channel is
// gone — status reports the LOCAL discovery registry instead.
package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// freshHome isolates the platform state for one test.
func freshHome(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// subprocEnv builds the hermetic environment for one binary invocation:
// HOME/GSEER_HOME point at the test's own state dir; all config-bearing
// env vars are cleared ("" is treated as UNSET by the env layer).
func subprocEnv(home string, extra map[string]string) []string {
	env := []string{
		"HOME=" + home,
		"GSEER_HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"GORELEASER_CURRENT_TAG=",
		"GSEER_CONFIG=",
		"GSEER_PROFILE=",
		"GSEER_DB_DSN=",
		"GSEER_UPDATE_MANIFEST_URL=",
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// gseerTestBin builds the real binary once per test process (warm build
// cache makes this a no-op after the first call).
var (
	gseerBinOnce  sync.Once
	gseerBinPath  string
	gseerBinError error
)

func gseerTestBin(t *testing.T) string {
	t.Helper()
	gseerBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gseer-status-test-bin-")
		if err != nil {
			gseerBinError = err
			return
		}
		bin := filepath.Join(dir, "gseer")
		cmd := exec.Command(goTool(), "build", "-o", bin, "./cmd/gseer")
		cmd.Dir = moduleRoot(t) // the test binary's cwd is internal/cli
		if out, err := cmd.CombinedOutput(); err != nil {
			gseerBinError = err
			t.Logf("go build failed: %s", out)
			return
		}
		gseerBinPath = bin
	})
	if gseerBinError != nil {
		t.Fatalf("cannot build the test binary: %v", gseerBinError)
	}
	return gseerBinPath
}

// goTool resolves the go binary (GO is present on every test machine).
func goTool() string {
	if g, err := exec.LookPath("go"); err == nil {
		return g
	}
	return "go"
}

// runGseer runs the binary with the hermetic environment and returns
// (stdout+stderr, exit code).
func runGseer(t *testing.T, home string, extra map[string]string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(gseerTestBin(t), args...) // #nosec G204 -- the test-built binary path
	cmd.Env = subprocEnv(home, extra)
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return buf.String(), code
}

func TestSubprocStatusFreshMachine(t *testing.T) {
	home := freshHome(t)
	out, code := runGseer(t, home, nil, "status")
	if code != 0 {
		t.Fatalf("status exited %d\noutput: %s", code, out)
	}
	for _, want := range []string{"not provisioned", "no local registry yet"} {
		if !strings.Contains(out, want) {
			t.Fatalf("fresh-machine status output missing %q:\n%s", want, out)
		}
	}
	// JSON view: valid, with the honest null discovery section.
	outJSON, code := runGseer(t, home, nil, "status", "-o", "json")
	if code != 0 {
		t.Fatalf("status -o json exited %d\noutput: %s", code, outJSON)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(outJSON), &v); err != nil {
		t.Fatalf("status -o json is not valid JSON: %v\n%s", err, outJSON)
	}
	if got, ok := v["discovery"]; !ok || got != nil {
		t.Fatalf("fresh-machine JSON discovery must be null, got: %v", got)
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

// TestSubprocStatusAfterPersonalSetup pins the CLI-only freshness
// contract: after a plain (offline-safe) personal setup the status
// shows the personal profile, the provisioned database file, and the
// honest "no sources registered yet" discovery state.
func TestSubprocStatusAfterPersonalSetup(t *testing.T) {
	home := freshHome(t)
	out, code := runGseer(t, home, nil, "setup", "--personal")
	if code != 0 {
		t.Fatalf("setup --personal exited %d\noutput: %s", code, out)
	}
	out, code = runGseer(t, home, nil, "status")
	if code != 0 {
		t.Fatalf("status exited %d\noutput: %s", code, out)
	}
	for _, want := range []string{"personal", "0 source(s) registered"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "shared index") {
		t.Fatalf("status must not reference the removed shared-index channel:\n%s", out)
	}
}
