// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// first_run.go — the zero-configuration entry point (v0.3.0).
//
// Bare `gseer`:
//   - `--version`              → the version block (the flag existed
//     since M1 but was never consumed — fixed here);
//   - no config file           → auto-initialize personal mode (one
//     SQLite file; no database server, no Docker) and show the user
//     how data enters the index;
//   - a config file exists     → a short, honest status plus the most
//     useful next commands (read-only; never a panic).
//
// The goal is the Fresh Install path: `go install … && gseer` ends
// with a working engine and a user who knows what to do next.
//
// v0.3.2 CLI-only architecture: the shared-index download path and the
// client profile are gone — the real-data path is the local passive
// discovery bootstrap (`gseer setup`).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
	"github.com/Lutfifakee-Project/gseer/internal/version"
)

// zeroConfigFirstRunApplies reports whether this invocation is in the
// "no configuration anywhere" state the zero-configuration first run
// covers: no --config/GSEER_CONFIG path override, no explicit profile
// selection (--profile, GSEER_PROFILE), and no platform-default config
// file (resolved GSEER_HOME-aware — a GSEER_HOME install with no config
// inside it is still fresh).  An explicit operator choice is never
// silently overridden — those paths keep their honest E_CONFIG errors.
func zeroConfigFirstRunApplies() bool {
	if flags.configPath != "" || flags.profile != "" {
		return false
	}
	for _, k := range []string{"GSEER_CONFIG", "GSEER_PROFILE"} {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			return false
		}
	}
	// The exact file config.Load resolves as the platform default
	// (config.DefaultConfigPath: $GSEER_HOME/config.yaml when GSEER_HOME
	// is set, else UserHomeDir/.gseer/config.yaml — the loader's own
	// resolution, so the CLI and the loader can no longer disagree about
	// whether state exists).
	if _, serr := os.Stat(config.DefaultConfigPath()); serr == nil {
		return false
	}
	return true
}

// engineConfigOrInit loads the configuration for engine commands with
// the zero-configuration first run applied: when nothing is configured
// anywhere, the standard personal-mode initialization runs first — the
// SAME runSetupPersonal path bare `gseer` uses (same permissions, same
// migrations, same config writer; no second init code path to drift) —
// and the freshly written config is loaded.  Engine commands therefore
// behave identically however the user orders their first steps:
// `gseer`, `gseer search …`, or `gseer source add …` all end in a
// working personal engine.
func engineConfigOrInit(cmd *cobra.Command) (*config.Config, error) {
	if cmd == nil {
		// Callers without a command context (package-level config
		// helpers) still get a working notice writer + background
		// context through an empty cobra Command.
		cmd = &cobra.Command{}
	}
	if zeroConfigFirstRunApplies() {
		out := cmd.OutOrStdout()
		if !flags.quiet {
			printf(out, "First GSEER run — initializing PERSONAL MODE (one local SQLite file; no database server, no Docker).\n\n")
		}
		if err := runSetupPersonal(cmd, "", false); err != nil {
			return nil, err
		}
		if !flags.quiet {
			printf(out, "\n")
		}
	}
	cfg, cerr := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
	})
	if cerr != nil {
		return nil, fmt.Errorf("E_CONFIG: %s", cerr.Error())
	}
	return cfg, nil
}

// runFirstRun implements the bare `gseer` invocation.
func runFirstRun(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()

	if flags.showVer {
		_, err := fmt.Fprint(out, version.Current().String())
		return err
	}

	cfgPath := flags.configPath
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return runStatus(cmd)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("E_CONFIG: cannot inspect %s: %w", cfgPath, err)
	}

	// First run: provision personal mode through the standard setup path
	// (same permissions, same migrations, same config writer — no second
	// initialization code path to drift).
	if !flags.quiet {
		printf(out, "Welcome to GSEER — internet-asset search engine.\n")
		printf(out, "No config at %s — initializing PERSONAL MODE (one local SQLite file; no database server, no Docker).\n\n", cfgPath)
	}
	if err := runSetupPersonal(cmd, "", false); err != nil {
		return err
	}
	if !flags.quiet {
		printf(out, "\nWhere does the data come from? GSEER stores only what YOU collect or import.\n")
		printf(out, "  try it now:  gseer setup                 (bootstrap passive discovery into the Local Index)\n")
		printf(out, "  synthetic:   gseer setup --load-fixtures (labeled evaluation corpus — NOT real internet data)\n")
		printf(out, "  manual:      gseer source add my-dns --type dns --seeds <domains> --enable --yes && gseer collect run\n")
		printf(out, "  full check:  gseer doctor\n")
	}
	return nil
}

// runStatus is the later-runs panel: what is configured, what the
// personal index holds, and the shortest path to the next useful
// action.  Read-only by contract.
func runStatus(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	if err := printBanner(out); err != nil {
		return err
	}
	cfg, err := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
	})
	if err != nil {
		return fmt.Errorf("E_CONFIG: %s\nTry: gseer doctor", err.Error())
	}
	printf(out, "\n")
	switch cfg.Profile {
	case config.ProfilePersonal:
		printf(out, "profile: personal (database: %s)\n", cfg.Database.DSN)
		printPersonalIndex(cmd, cfg)
	default:
		printf(out, "profile: self-hosted (PostgreSQL)\n")
		printf(out, "  checks:    gseer doctor\n")
		printf(out, "  search:    gseer search 'port==443'\n")
		printf(out, "  collect:   gseer collect run --all\n")
	}
	printf(out, "  all commands: gseer --help\n")
	return nil
}

// printPersonalIndex reports the personal index contents (read-only;
// a missing or unreadable database file is an honest hint, never a
// panic).
func printPersonalIndex(cmd *cobra.Command, cfg *config.Config) {
	out := cmd.OutOrStdout()
	svc, closeDB, err := personalSearchService(cfg)
	if err != nil {
		printf(out, "  index:    not readable (%v)\n  fix:      gseer setup --personal\n", err)
		return
	}
	defer closeDB()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	meta, err := svc.Stats(ctx)
	if err != nil {
		printf(out, "  index:    not readable (%v)\n", err)
		return
	}
	switch {
	case meta.Empty:
		printf(out, "  index:    EMPTY — nothing collected yet\n")
		printf(out, "  fastest:  gseer setup   (bootstrap passive discovery — real internet assets into the Local Index)\n")
		printf(out, "  try it:   gseer setup --load-fixtures   (labeled synthetic evaluation corpus)\n")
		printf(out, "  manual:   gseer source add my-dns --type dns --seeds <domains> --enable --yes\n")
		printf(out, "            gseer collect run --source my-dns\n")
	case meta.FixtureOnly:
		printf(out, "  index:    %d assets, %d services, %d observations (SYNTHETIC fixture data — not real internet data)\n",
			meta.Assets, meta.Services, meta.Observations)
		printf(out, "  real:     gseer setup   (bootstrap passive discovery)  or  gseer source add my-dns --type dns --seeds <domains> --enable --yes\n")
	default:
		printf(out, "  index:    %d assets, %d services, %d observations\n",
			meta.Assets, meta.Services, meta.Observations)
	}
	printDiscoveryFreshness(cmd)
}

// printDiscoveryFreshness reports the local discovery state (read-only;
// an absent or unreadable database is an honest hint, never a panic).
// v0.3.2: the status panel surfaces LOCAL discovery freshness —
// Easy-to-Use includes knowing HOW FRESH the evidence is.
func printDiscoveryFreshness(cmd *cobra.Command) {
	out := cmd.OutOrStdout()
	cfg, err := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
	})
	if err != nil || cfg.Profile != config.ProfilePersonal {
		return
	}
	res, derr := openPersonal(cfg)
	if derr != nil {
		return // the index block above already reported the DB problem
	}
	defer func() { _ = res.DB.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store := sqlite.NewStore(res.DB)
	sources, serr := store.ListSources(ctx)
	if serr != nil {
		return
	}
	enabled := 0
	for _, s := range sources {
		if s.Enabled {
			enabled++
		}
	}
	if len(sources) == 0 {
		printf(out, "  sources:  none registered yet — run: gseer setup\n")
		return
	}
	var lastRun time.Time
	_ = res.DB.QueryRowContext(ctx,
		"SELECT MAX(COALESCE(finished_at, started_at)) FROM collection_jobs WHERE status = 'success'").Scan(&lastRun)
	if lastRun.IsZero() {
		printf(out, "  sources:  %d registered (%d enabled) — no successful collect run yet\n", len(sources), enabled)
		return
	}
	printf(out, "  sources:  %d registered (%d enabled); last successful collect %s (%s ago)\n",
		len(sources), enabled,
		lastRun.UTC().Format("2006-01-02 15:04 UTC"), time.Since(lastRun).Round(time.Second))
}
