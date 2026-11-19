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
	"io"

	"github.com/Lutfifakee-Project/gseer/internal/version"
	"github.com/spf13/cobra"
)

// bannerTemplate is the GSEER ASCII banner.  The final %s is replaced by
// the dynamic version string (v-prefixed).  Backslashes in the ASCII art
// are literal because this is a raw string.
const bannerTemplate = `
   ___________ ________________ 
  / ____/ ___// ____/ ____/ __ \
 / / __ \__ \/ __/ / __/ / /_/ /
/ /_/ /___/ / /___/ /___/ _, _/ 
\____//____/_____/_____/_/ |_|%s`

// bannerVersion returns the display version string for the banner,
// prefixed with two spaces so the version sits at the right edge of the
// last banner line (e.g. "|_|  v0.1.0").  Since the Rev16 fix the
// canonical "v"-prefixed form is produced by ONE choke point —
// version.Current() (normalizeVersion) — which every surface shares, so
// the banner can no longer disagree with status/doctor/`gseer version`
// (previously this function de-duplicated the prefix locally while the
// other surfaces echoed the raw injected string, so a v-prefixed
// snapshot build rendered "v0.3.1-snapshot" here but "vv0.3.1-snapshot"
// everywhere else — the Rev16 owner-acceptance finding).  Empty build
// metadata still falls back to "dev".
func bannerVersion() string {
	v := version.Current().Version
	if v == "" {
		v = "dev"
	}
	return "  " + v
}

// printBanner renders the GSEER ASCII banner to w.  When the quiet flag
// is set, nothing is printed.  Returns any write error from the writer.
func printBanner(w io.Writer) error {
	if flags.quiet {
		return nil
	}
	_, err := fmt.Fprintf(w, "%s\n", fmt.Sprintf(bannerTemplate, bannerVersion()))
	return err
}

// bannerHelpFunc wraps RootCmd's help rendering so the ASCII banner is
// printed before the help text for root-level invocations
// (`gseer`, `gseer --help`, `gseer help`).  Subcommand help
// (`gseer search --help`) uses the default cobra help func and prints
// no banner.
//
// cobra's HelpFunc() walks up the parent chain when a command has no
// helpFunc of its own, so subcommands inherit RootCmd's func.  We skip
// the banner when cmd has a parent (i.e. it is a subcommand).
//
// To render the subcommand's help without infinite recursion
// (cmd.Help() → HelpFunc() → parent → bannerHelpFunc → ...), we
// temporarily clear RootCmd's helpFunc so cmd.Help() falls through to
// cobra's default help rendering, then restore it.
func bannerHelpFunc(cmd *cobra.Command, args []string) {
	if !cmd.HasParent() {
		if err := printBanner(cmd.OutOrStdout()); err != nil {
			cmd.PrintErrln(err)
		}
	}
	// Walk up to RootCmd.
	root := cmd
	for root.HasParent() {
		root = root.Parent()
	}
	origRootHelp := root.HelpFunc()
	root.SetHelpFunc(nil)
	defer root.SetHelpFunc(origRootHelp)
	if err := cmd.Help(); err != nil {
		cmd.PrintErrln(err)
	}
}
