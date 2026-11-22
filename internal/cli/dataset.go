// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// dataset.go — `gseer dataset` (v0.3.2 Rev 9): the central
// internet-asset dataset channel.
//
//	gseer dataset update [--check] [--manifest-url URL] [--force]
//	    download the manifest → verify the payload checksum + record
//	    count → import into the Local Index ATOMICALLY (pre-import
//	    snapshot; any failure rolls back; interrupted imports recover).
//	    Without a re-setup: the explicit refresh path (#7).
//	gseer dataset check
//	    manifest-only: version, freshness, provenance (no download of
//	    the payload, no database contact).
//	gseer dataset status
//	    the installed dataset state (version, imported_at, freshness).
//
// Search stays LOCAL — the dataset only FEEDS the index (no shared-index
// query service), and search never triggers discovery or scanning.

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

func registerDatasetCmd(root *cobra.Command) {
	datasetCmd := &cobra.Command{
		Use:   "dataset",
		Short: "Central dataset channel (update, check, status)",
		Long: `Manage the central internet-asset dataset (docs/DATASET.md).

The project's scheduled pipeline publishes a versioned, checksummed
dataset of validated passive-discovery evidence.  update downloads the
manifest, verifies the payload checksum, and imports it into the Local
Index ATOMICALLY — the same ingestion path, suppression gate, and
delivery-identity dedupe as every other writer; provenance and
observed_at are preserved, and the import rolls back on any failure.

Search stays local: the dataset only FEEDS the index.`,
		Args: cobra.NoArgs,
	}
	datasetCmd.AddCommand(newDatasetUpdateCmd(), newDatasetCheckCmd(), newDatasetStatusCmd())
	root.AddCommand(datasetCmd)
}

// resolveManifestURL resolves the dataset channel: --manifest-url >
// dataset.manifest_url (config/env) > the official project channel.
func resolveManifestURL(cfg *config.Config, override string) string {
	if override != "" {
		return override
	}
	if cfg.Dataset.ManifestURL != "" {
		return cfg.Dataset.ManifestURL
	}
	return config.OfficialDatasetManifestURL
}

func newDatasetUpdateCmd() *cobra.Command {
	var (
		manifestURL string
		force       bool
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Download, verify, and atomically import the latest central dataset",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDatasetUpdate(cmd, manifestURL, force)
		},
	}
	cmd.Flags().StringVar(&manifestURL, "manifest-url", "", "dataset manifest URL (default: the official project channel)")
	cmd.Flags().BoolVar(&force, "force", false, "re-import even when the installed version is current")
	return cmd
}

func runDatasetUpdate(cmd *cobra.Command, manifestURL string, force bool) error {
	out := cmd.OutOrStdout()
	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		printf(out, "%s\nTry: gseer setup --help\n", cerr.Error())
		exitWith(ExitConfig)
		return nil
	}
	if cfg.Profile != config.ProfilePersonal {
		printf(out, "E_USAGE: the central dataset imports into the personal Local Index (profile: %s).\n"+
			"Try: gseer setup  (personal mode provisions the Local Index and auto-imports the dataset)\n", cfg.Profile)
		exitWith(ExitUsagePlanned)
		return nil
	}

	channel := resolveManifestURL(cfg, manifestURL)
	fetcher := dataset.NewFetcher()
	ctx := commandContext(cmd)

	printf(out, "[ ..  ] dataset: checking the manifest (%s)\n", channel)
	manifest, err := fetcher.FetchManifest(ctx, channel)
	if err != nil {
		printf(out, "%s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}

	// Version gate: refuse older/equal without --force (idempotent
	// re-import stays possible with --force).
	state, err := loadDatasetState(cmd, cfg)
	if err != nil {
		printf(out, "E_DB: %s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	if state.Installed && !force && manifest.DatasetVersion <= state.DatasetVersion {
		printf(out, "[ ok  ] dataset: already at version %d (channel offers %d) — nothing to do\n",
			state.DatasetVersion, manifest.DatasetVersion)
		printDatasetFreshness(out, manifest, state)
		return nil
	}

	printf(out, "[ ..  ] dataset v%d: %d records, generated %s (downloading + verifying the payload)\n",
		manifest.DatasetVersion, manifest.Payload.Records, manifest.GeneratedAtUTC.UTC().Format("2006-01-02 15:04 UTC"))
	payloadPath, err := fetcher.FetchPayload(ctx, channel, manifest)
	if err != nil {
		printf(out, "%s\n", err.Error())
		exitWith(ExitInvalidInput)
		return nil
	}
	defer func() { _ = removeFile(payloadPath) }()

	printf(out, "[ ok  ] payload verified: sha256 %s (%d bytes, %d records)\n",
		manifest.Payload.SHA256[:12]+"…", manifest.Payload.SizeBytes, manifest.Payload.Records)
	result, err := dataset.Import(ctx, dataset.ImportOptions{
		DBPath:      cfg.Database.DSN,
		PayloadPath: payloadPath,
		Manifest:    manifest,
		ManifestURL: channel,
	})
	if err != nil {
		printf(out, "%s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	if result.Recovered {
		printf(out, "[ ok  ] recovered: an interrupted import's snapshot was restored before this import\n")
	}
	printf(out, "[ ok  ] dataset v%d imported: %d observations ingested, %d deduped, %d suppressed by YOUR rules\n",
		manifest.DatasetVersion, result.Stats.ObservationsInserted, result.Stats.ObservationsDeduped, result.Stats.Suppressed)
	printDatasetFreshness(out, manifest, nil)
	printf(out, "Search it:  gseer search 'port=443'   (search stays local — it never triggers discovery or scanning)\n")
	return nil
}

func newDatasetCheckCmd() *cobra.Command {
	var manifestURL string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check the channel's latest dataset manifest (no payload download)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				printf(out, "%s\nTry: gseer setup --help\n", cerr.Error())
				exitWith(ExitConfig)
				return nil
			}
			channel := resolveManifestURL(cfg, manifestURL)
			manifest, err := dataset.NewFetcher().FetchManifest(commandContext(cmd), channel)
			if err != nil {
				printf(out, "%s\n", err.Error())
				exitWith(ExitUnavailable)
				return nil
			}
			printf(out, "[ ok  ] channel: %s\n", channel)
			printf(out, "  version      : %d (generated %s)\n",
				manifest.DatasetVersion, manifest.GeneratedAtUTC.UTC().Format("2006-01-02 15:04 UTC"))
			printf(out, "  payload      : %d records, sha256 %s…, %d bytes\n",
				manifest.Payload.Records, manifest.Payload.SHA256[:12], manifest.Payload.SizeBytes)
			printf(out, "  rows         : %d assets, %d service-bearing records\n",
				manifest.Rows.Assets, manifest.Rows.Services)
			printDatasetFreshness(out, manifest, nil)
			for _, p := range manifest.Provenance {
				printf(out, "  provenance   : %s (%s) — %d records, newest observed %s\n",
					p.Source, p.Connector, p.Records, p.NewestObservedAt.UTC().Format("2006-01-02 15:04 UTC"))
			}
			if manifest.Notes != "" {
				printf(out, "  coverage     : %s\n", manifest.Notes)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&manifestURL, "manifest-url", "", "dataset manifest URL (default: the official project channel)")
	return cmd
}

func newDatasetStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the installed dataset state (version, freshness)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				printf(out, "%s\nTry: gseer setup --help\n", cerr.Error())
				exitWith(ExitConfig)
				return nil
			}
			state, err := loadDatasetState(cmd, cfg)
			if err != nil {
				printf(out, "E_DB: %s\n", err.Error())
				exitWith(ExitUnavailable)
				return nil
			}
			if !state.Installed {
				printf(out, "  dataset     : not imported yet\n")
				printf(out, "  Try         : gseer dataset update   (or: gseer setup — imports automatically)\n")
				return nil
			}
			printf(out, "  dataset     : version %d imported %s\n",
				state.DatasetVersion, orNeverTime(&state.ImportedAt))
			printf(out, "  channel     : %s\n", state.ManifestURL)
			printf(out, "  payload     : %d records (sha256 %s…)\n", state.Records, head12(state.PayloadSHA256))
			printf(out, "  freshness   : observed %s .. %s (UTC)\n",
				orNeverTime(&state.OldestObservedAt), orNeverTime(&state.NewestObservedAt))
			return nil
		},
	}
}

// loadDatasetState opens the personal database and reads the dataset
// install state (read-only intent; sqlite.Open creates nothing when the
// file exists — the engine commands provisioned it already).
// datasetFetcherFromConfig builds the fetcher the CLI uses, applying the
// config's trusted redirect hosts (R4 P0-5).  An UNSET list (nil) keeps
// NewFetcher's product defaults (the official GitHub release-asset CDN);
// an explicitly configured list replaces the defaults verbatim — an
// empty list trusts nothing (strict fail-closed).
func datasetFetcherFromConfig(cfg *config.Config) *dataset.Fetcher {
	f := dataset.NewFetcher()
	if cfg != nil && cfg.Dataset.TrustedRedirectHosts != nil {
		f.TrustedRedirectHosts = cfg.Dataset.TrustedRedirectHosts
	}
	return f
}

func loadDatasetState(cmd *cobra.Command, cfg *config.Config) (*dataset.State, error) {
	res, err := openPersonal(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot open the personal database: %w", err)
	}
	defer func() { _ = res.DB.Close() }()
	return dataset.LoadState(commandContext(cmd), res.DB)
}

func printDatasetFreshness(out interface{ Write([]byte) (int, error) }, manifest *dataset.Manifest, state *dataset.State) {
	oldest, newest := manifest.Freshness.OldestObservedAt, manifest.Freshness.NewestObservedAt
	if state != nil {
		oldest, newest = state.OldestObservedAt, state.NewestObservedAt
	}
	age := ""
	if !newest.IsZero() {
		age = fmt.Sprintf(" (newest evidence %s old)", time.Since(newest).Round(time.Second))
	}
	printf(out, "  freshness   : evidence observed %s .. %s UTC%s\n",
		orNeverTime(&oldest), orNeverTime(&newest), age)
}

func orNeverTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func head12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func removeFile(path string) error {
	if path == "" {
		return nil
	}
	return os.Remove(path)
}
