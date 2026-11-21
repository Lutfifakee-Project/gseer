// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package main is the entry point for the single `gseer` binary.  All
// command dispatch lives in internal/cli; main is deliberately tiny so
// the cobra root command controls exit codes (AC-5.x exit code matrix).
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
