// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// registerComingLaterCmds registers the planned-but-absent command
// `asset`.  It is registered so that `gseer asset` does
// not fall through to cobra's generic "unknown command" suggestion;
// instead it prints the honest pointer line and exits 64.
//
// (`scan` graduated to a real command in v0.3.2 — scan.go, behind the
// default-deny gateway; it is no longer a coming-later stub.)
//
// This command is NOT listed in the top-level "Commands:" section of
// help (it appears only in the "Coming later" pointer line); it is
// hidden from cobra's auto-completion and help listing via Hidden=true.
func registerComingLaterCmds(root *cobra.Command) {
	for _, name := range []string{"asset"} {
		cmd := &cobra.Command{
			Use:    name,
			Short:  "Planned, not in this release — see CHANGELOG.md",
			Hidden: true, // not in the top-level Commands: listing
			// DisableFlagParsing so any flag (e.g. `gseer update --check`,
			// `gseer scan --target ...`) reaches RunE rather than tripping
			// cobra's "unknown flag" error.  The pointer line fires either
			// way; the user gets the honest message and exit 64.
			DisableFlagParsing: true,
			// Accept any args for the same reason.
			Args: cobra.ArbitraryArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				// We are about to exit(64); write errors are not
				// recoverable here, so we explicitly discard them.
				// exitFunc (the process-exit seam shared with search.go)
				// keeps this testable.
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
					"E_NOT_IMPLEMENTED: \"gseer %s\" is planned, not in this release.\n",
					cmd.Name())
				if cmd.Name() == "asset" {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Asset detail view is planned for a later release — see CHANGELOG.md for what each release shipped.")
				}
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Exit code 64.")
				exitFunc(ExitUsagePlanned)
				return nil // unreachable; exitFunc terminates
			},
		}
		root.AddCommand(cmd)
	}
}
