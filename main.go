// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package main exists for exactly ONE reason (REL-01): the Go module
// root is the package path resolved by the short-form install command
//
//	go install github.com/Lutfifakee-Project/gseer@latest
//
// and `go install` requires a main package at the module root.  Without
// this file that command fails with "does not contain package" and the
// easy-install path documented in docs/INSTALL.md is broken.
//
// This file is a deliberate mirror of cmd/gseer/main.go — the canonical
// release entry point that GoReleaser builds (builds.main in
// .goreleaser.yaml).  It contains NO command logic of its own: all
// dispatch lives in internal/cli, so there is exactly one command tree
// and both entry points cannot diverge.  TestMain-equivalence is
// enforced by main_test.go, which builds BOTH entry points and asserts
// identical stdout and exit codes for representative invocations.
package main

import (
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/gseer/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		// Errors are formatted by the cli layer per the style guide
		// (what failed → likely why → exact next command, AC-5.9).  The
		// exit code is the cobra SilenceErrors contract — the cli layer
		// sets it via os.Exit when a specific code is required (e.g. 64
		// for reserved/planned commands per AC-5.7–5.8).
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
