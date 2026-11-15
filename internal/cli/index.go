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

// index.go — `gseer index` (v0.3.2): the shared-index lifecycle
// command (approved STAGE 4 scope items 1-3).
//
//	gseer index update [--check] [--force] [--manifest-url URL]
//	    run the full trust chain: verify the SIGNED manifest → sequence
//	    gate → download the snapshot → checksum → validate (integrity,
//	    schema, counts) → atomic install (previous snapshot kept as
//	    .prev) → import into the personal store (L1/L2 dedup; provenance
//	    "shared-index").
//	gseer index status
//	    report the installed sequence, freshness, and manifest channel.
//
// Exit codes: verification/trust failures (unsigned, bad signature)
// are exit 5 (auth — you cannot trust this artifact); network and
// availability failures are exit 4 (unavailable — per the SPEC-03 §9
// table, which names index explicitly); usage errors follow the
// standard codes.  `gseer index update` never scans, never collects,
// and imports nothing but the verified snapshot rows.

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/index"
)

func registerIndexCmd(root *cobra.Command) {
	idx := &cobra.Command{
		Use:   "index",
		Short: "Shared-index lifecycle: update/status of the signed internet-asset index",
		Args:  cobra.NoArgs,
		Long: `Manage the shared index — the project's versioned, signed snapshot of
collected internet assets (docs/SHARED-INDEX.md).

Every update runs the full trust chain (verification FIRST, download
LAST — mirrors the signed binary updater):

  1. SIGNATURE   the manifest must verify against the Ed25519 key
                 embedded in this binary; unsigned manifests are refused
  2. SEQUENCE    only strictly-newer sequences install (--force overrides)
  3. CHECKSUM    SHA-256 + size must match the manifest exactly
  4. VALIDITY    SQLite integrity_check, schema compatibility, and the
                 exact row counts the manifest claims
  5. ATOMIC      the previous snapshot is preserved (.prev) until the
                 new one is fully verified and renamed into place
  6. IMPORT      rows merge into the personal store through the same
                 upsert/dedup contracts live collection uses; search
                 results label them provenance=shared-index

Examples:
  gseer index update --check       freshness check (no download)
  gseer index update               fetch + verify + install + import
  gseer index status               what is installed and how fresh`,
	}
	idx.AddCommand(newIndexUpdateCmd(), newIndexStatusCmd())
	root.AddCommand(idx)
}

func newIndexUpdateCmd() *cobra.Command {
	var (
		check       bool
		force       bool
		manifestURL string
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Fetch, verify, install, and import the latest shared index",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadEngineConfig()
			if err != nil {
				return err
			}
			if cfg.Profile != config.ProfilePersonal {
				return fmt.Errorf("E_PROFILE_MISMATCH: the shared index imports into the personal store (current profile: %s).\n"+
					"Try: gseer setup  (personal mode + shared index) or gseer setup --personal", cfg.Profile)
			}
			url := manifestURL
			if url == "" {
				url = cfg.Index.ManifestURL
			}
			if url == "" {
				url = config.OfficialIndexManifestURL
			}
			store, res, err := personalStore(commandContext(cmd), cfg)
			if err != nil {
				return err
			}
			defer func() { _ = res.DB.Close() }()

			out := cmd.OutOrStdout()
			opts := index.Options{
				ManifestURL: url,
				Dir:         sharedIndexDir(),
				Store:       store,
				Force:       force,
			}
			if check {
				r, cerr := index.Check(commandContext(cmd), opts)
				if cerr != nil {
					return indexFailure(cmd, cerr)
				}
				printf(out, "manifest channel: %s\n", r.ManifestURL)
				printf(out, "remote sequence:  %d (built %s)\n", r.RemoteSeq, fmtTime(r.Remote.BuiltAt))
				printf(out, "local sequence:   %d\n", r.LocalSeq)
				if r.UpToDate {
					printf(out, "status: UP TO DATE (nothing to do; use --force to re-install)\n")
				} else {
					printf(out, "status: UPDATE AVAILABLE — run: gseer index update\n")
				}
				return nil
			}

			r, uerr := index.Update(commandContext(cmd), opts)
			if uerr != nil {
				return indexFailure(cmd, uerr)
			}
			printf(out, "[ ok  ] manifest verified (signature, sequence %d, built %s)\n", r.RemoteSeq, fmtTime(r.Remote.BuiltAt))
			if r.UpToDate && !r.Installed {
				printf(out, "[ ok  ] already at sequence %d — nothing to do (use --force to re-install)\n", r.LocalSeq)
				if r.ImportResult != nil {
					renderImport(out, r.ImportResult)
				}
				return nil
			}
			printf(out, "[ ok  ] snapshot verified (SHA-256, integrity_check, schema v%d, counts match)\n", r.Remote.SchemaVersion)
			printf(out, "[ ok  ] installed atomically (previous snapshot kept as .prev)\n")
			if r.ImportResult != nil {
				renderImport(out, r.ImportResult)
			} else {
				printf(out, "[warn] installed but NOT imported (no personal store) — run: gseer setup\n")
			}
			printf(out, "\nSearch it with: gseer search 'nginx'\n")
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "verify the manifest and report freshness only (no snapshot download)")
	cmd.Flags().BoolVar(&force, "force", false, "re-install even when the remote sequence is not newer")
	cmd.Flags().StringVar(&manifestURL, "manifest-url", "", "override the signed manifest URL (https; http only for loopback)")
	return cmd
}

func newIndexStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report the installed shared index (sequence, freshness, channel)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			dir := sharedIndexDir()
			st, err := index.LoadState(dir)
			if err != nil {
				return err
			}
			if st == nil {
				printf(out, "no shared index installed in %s\n", dir)
				printf(out, "Try: gseer setup  (personal mode + shared index) or gseer index update\n")
				return nil
			}
			age := time.Since(st.BuiltAt).Round(time.Second)
			printf(out, "installed sequence: %d (built %s, age %s)\n", st.Sequence, fmtTime(st.BuiltAt), age)
			printf(out, "artifact sha256:    %s\n", st.ArtifactSHA)
			printf(out, "manifest channel:   %s\n", st.ManifestURL)
			printf(out, "imported into store: %v\n", st.Imported)
			if !st.Imported {
				printf(out, "Try: gseer index update  (re-runs the import; idempotent)\n")
			}
			if age > 14*24*time.Hour {
				printf(out, "[warn] the index is older than two weeks — refresh: gseer index update\n")
			}
			return nil
		},
	}
}

// sharedIndexDir resolves the local index directory
// (<platform config dir>/index — ~/.gseer/index on Linux).
func sharedIndexDir() string {
	return filepath.Join(configDir(), "index")
}

// indexFailure renders an E_INDEX_* error and exits with the SPEC-03 §9
// code: trust failures are auth (5); availability failures are 4.
func indexFailure(cmd *cobra.Command, err error) error {
	printf(cmd.ErrOrStderr(), "%v\n", err)
	msg := err.Error()
	switch {
	case strings.Contains(msg, "E_INDEX_UNSIGNED"), strings.Contains(msg, "E_INDEX_BAD_SIGNATURE"):
		exitWith(ExitAuth)
	default:
		exitWith(ExitUnavailable)
	}
	return nil
}

func renderImport(out interface{ Write([]byte) (int, error) }, r *index.ImportRes) {
	printf(out, "[ ok  ] imported: %d assets inserted, %d updated; %d services inserted, %d updated; %d observations inserted, %d deduped\n",
		r.AssetsInserted, r.AssetsUpdated, r.ServicesInserted, r.ServicesUpdated, r.ObservationsInserted, r.ObservationsDeduped)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "(unknown)"
	}
	return t.UTC().Format(time.RFC3339)
}
