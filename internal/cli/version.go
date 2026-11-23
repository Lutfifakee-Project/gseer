// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"fmt"

	"github.com/Lutfifakee-Project/gseer/internal/version"
	"github.com/spf13/cobra"
)

// registerVersionCmd attaches the `gseer version` command (SPEC-03 §2).
//
// Output is the multi-line block from version.Info.String(): version,
// commit, built_at, go version.  The fields are injected via -ldflags in
// the Makefile/CI; an un-injected binary reports "dev" / "unknown" rather
// than fabricating values (the honesty floor, AC-8.x).
func registerVersionCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version, commit, and build info",
		Long: `Show version, commit, and build info.

The version, commit, and built_at fields are injected at build time via
-ldflags; an un-injected binary (e.g. 'go run') reports 'dev' and
'unknown' rather than fabricating values.  'gseer doctor' prints the
running binary's SHA-256 for checksum verification.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprint(cmd.OutOrStdout(), version.Current().String())
			return err
		},
	}
	root.AddCommand(cmd)
}
