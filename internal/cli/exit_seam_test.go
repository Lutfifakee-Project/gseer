// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import "testing"

// exit_seam_test.go — the shared process-exit seam guard for CLI tests.
// The shared RootCmd leaks persistent cobra flags between tests (see
// search.go's searchFlagsReset comment), so a RunE that hits an exitWith
// path would otherwise os.Exit the whole test binary.  pinExitFunc
// substitutes the seam for one test and restores it via t.Cleanup; tests
// inspect guard.called to assert WHICH exit code a path took.

type exitGuard struct {
	called *int
}

// pinExitFunc substitutes exitWith/exitFunc with a recorder for the
// duration of one test.
func pinExitFunc(t *testing.T) *exitGuard {
	t.Helper()
	g := &exitGuard{}
	orig := exitFunc
	exitFunc = func(code int) {
		c := code
		g.called = &c
	}
	t.Cleanup(func() { exitFunc = orig })
	return g
}
