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

import (
	"fmt"

	"github.com/spf13/cobra"
)

// registerComingLaterCmds registers the planned-but-absent command
// `asset` (SPEC-03 §2).  It is registered so that `gseer asset` does
// not fall through to cobra's generic "unknown command" suggestion;
// instead it prints the honest pointer line and exits 64 (AC-5.7–5.8).
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
			Short:  "Planned, not in this release — see docs/ROADMAP.md",
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
				switch cmd.Name() {
				case "asset":
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Asset detail view is planned for a later release — see docs/ROADMAP.md.")
				}
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Exit code 64.")
				exitFunc(ExitUsagePlanned)
				return nil // unreachable; exitFunc terminates
			},
		}
		root.AddCommand(cmd)
	}
}
