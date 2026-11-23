// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/postgres"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
	"github.com/Lutfifakee-Project/gseer/internal/version"
)

// doctor.go — `gseer doctor` (SPEC-03 §2; QS-4).
//
// M1 registered the command; M3 wires the DB-side checks (config
// validity, DB reachable + PG version, migrations at head) using the
// storage-layer check assembler.  The remaining QS-4 checks (binary
// checksum, index contents, server reachability) land with M11 when
// the fixtures and server exist — the help text and output are honest
// about which checks are wired (AC-8.x).
//
// Doctor is strictly read-only: it never migrates and never forces.
// A dirty migration state FAILS with a pointer to
// `gseer db migrate diagnose` (owner directive §2, M3 round).

// registerDoctorCmd attaches `gseer doctor`.
func registerDoctorCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose config, connectivity, database, and index health",
		Long: `Diagnose config, connectivity, database, and index health.

Reports PASS/FAIL/HINT with a fix line for each check.
Wired:
  - config validity
  - DB reachable + PG version compatible (PostgreSQL 16+)
  - migrations at head (dirty state → gseer db migrate diagnose)
  - binary version / OS-arch / SHA-256 (self-reported; compare with the
    corresponding published release checksum when a binary release is
    available)
  - index contents: EMPTY | counts | fixture-labeled honesty label
  - discovery freshness (per-source registry state + last successful
    collection job age)
  - runtime credential + fail-closed privilege audit (self-hosted:
    PASS names the verified grants; FAIL names the failures;
    HINT when the runtime credential is not provisioned yet)
  - personal mode (v0.2.1): database file + permissions, SQLite migration
    state, and the same index-contents honesty contract (read-only: the
    doctor never creates or migrates the personal database)

Doctor MUST NOT show a generic "healthy" that hides an empty or fixture-
filled index.  Doctor is read-only: it never migrates.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			cfg, cerr := config.Load(config.Flags{
				ConfigPath: flags.configPath,
				Profile:    flags.profile,
			})
			pass, fail := 0, 0
			report := func(name, outcome, detail, fix string, err error) {
				switch outcome {
				case "PASS":
					pass++
					printf(out, "[ PASS ] %s: %s\n", name, detail)
				case "HINT":
					printf(out, "[ HINT ] %s: %s\n        Try: %s\n", name, detail, fix)
				case "SKIP":
					printf(out, "[ -    ] %s: %s\n", name, detail)
				default:
					fail++
					printf(out, "[ FAIL ] %s: %s\n", name, detail)
					if fix != "" {
						printf(out, "        Try: %s\n", fix)
					}
					if err != nil {
						// Render the full structured error (Code/Why/Try).
						printf(out, "        %s\n", strings.ReplaceAll(err.Error(), "\n", "\n        "))
					}
				}
			}

			// Zero-configuration first run: with no configuration anywhere
			// (and no explicit override), a missing config is not a fault —
			// the first engine command initializes personal mode.  Doctor
			// stays read-only: it reports the state, it never provisions.
			if cerr != nil && zeroConfigFirstRunApplies() {
				report("config validity", "PASS",
					"none yet — zero-config first run: the first engine command (gseer, search, source, collect) initializes personal mode automatically", "", nil)
				info := version.Current()
				report("binary", "PASS", fmt.Sprintf("version %s, commit %s, built %s, %s/%s, sha256=%s",
					info.Version, orUnknown(info.Commit), orUnknown(info.BuiltAt),
					runtime.GOOS, runtime.GOARCH, binarySHA256()), "", nil)
				report("database + index", "SKIP", "nothing initialized yet — run gseer (or any engine command) once, then re-run doctor", "gseer", nil)
				printf(out, "\n%d PASS, %d FAIL.\n", pass, fail)
				return nil
			}

			if cerr != nil {
				report("config validity", "FAIL", "configuration is invalid", "gseer setup --help", cerr)
				printf(out, "\n%d PASS, %d FAIL. Fix the failures above and re-run.\n", pass, fail)
				os.Exit(ExitConfig)
			}
			report("config validity", "PASS", "loaded "+cfg.Source+" (profile="+string(cfg.Profile)+")", "", nil)

			// Binary identity: version/commit/build + SHA-256.
			info := version.Current()
			report("binary", "PASS", fmt.Sprintf("version %s, commit %s, built %s, %s/%s, sha256=%s",
				info.Version, orUnknown(info.Commit), orUnknown(info.BuiltAt),
				runtime.GOOS, runtime.GOARCH, binarySHA256()), "", nil)

			if cfg.Profile == config.ProfilePersonal {
				reportPersonalDBChecks(cmd, cfg, report)
				printf(out, "\n%d PASS, %d FAIL", pass, fail)
				if fail > 0 {
					println(out, ". Fix the failures above and re-run.")
					os.Exit(ExitUnavailable)
				}
				println(out, ".")
				return nil
			}

			dsn := cfg.Database.EffectiveDSN()
			results := postgres.DoctorDBChecks(cmd.Context(), dsn, cfg.Defaults.PostgresMajor)
			for _, r := range results {
				report(r.Name, string(r.Outcome), r.Detail, r.Fix, r.Err)
			}

			// Hardened runtime credential + fail-closed privilege
			// audit (v0.2.0 OD-5/M-B/M-C).  Read-only like every
			// doctor check.
			reportRuntimeCredentialCheck(cmd, cfg, report)

			// Index contents (QS-4 honesty): empty vs counts vs fixture-labeled.
			reportIndexCheck(cmd, cfg, report)

			printf(out, "\n%d PASS, %d FAIL", pass, fail)
			if fail > 0 {
				println(out, ". Fix the failures above and re-run.")
				os.Exit(ExitUnavailable)
			}
			println(out, ".")
			return nil
		},
	}
	root.AddCommand(cmd)
}

// binarySHA256 returns the hex SHA-256 of the running executable (or
// "unavailable" when the path/content cannot be read — doctor stays
// honest about it).
func binarySHA256() string {
	path, err := os.Executable()
	if err != nil {
		return "unavailable"
	}
	b, err := os.ReadFile(path) // #nosec G304 -- reads the running binary itself (os.Executable) for the doctor fingerprint
	if err != nil {
		return "unavailable"
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// reportRuntimeCredentialCheck runs the hardened v0.2.0 check: when the
// gseer_app runtime credential is configured, the fail-closed effective-
// privilege audit runs UNDER THAT CREDENTIAL (every catalog it consults
// is readable by non-superusers, so a pass simultaneously proves the
// deployment state and the credential's own reach — OD-5).  Without the
// runtime credential the check is an honest HINT (doctor never pretends
// an unprovisioned deployment is hardened).
func reportRuntimeCredentialCheck(cmd *cobra.Command, cfg *config.Config, report func(name, outcome, detail, fix string, err error)) {
	runtimeDSN, explicit := cfg.Database.RuntimeCredentialDSN()
	if !explicit {
		report("runtime credential", "HINT",
			"gseer_app runtime credential is not configured (database.runtime_dsn / GSEER_DB_RUNTIME_DSN)",
			"the hardened self-hosted data plane expects it — provision with: gseer setup --self-hosted", nil)
		return
	}
	rep, err := postgres.RunPrivilegeAudit(commandContext(cmd), runtimeDSN)
	if err != nil {
		report("privilege audit", "FAIL",
			"the fail-closed privilege audit could not run under the runtime credential",
			"check database.runtime_dsn; an audit that cannot run is not an audit that passed", err)
		return
	}
	if !rep.Passed {
		report("privilege audit", "FAIL",
			fmt.Sprintf("the fail-closed privilege audit found %d failure(s): %s",
				len(rep.Failures), strings.Join(rep.Failures, " | ")),
			"fix the deployment, never the check — docs/DEPLOYMENT.md §3.5 (do NOT grant gseer_app more privileges)", nil)
		return
	}
	report("privilege audit", "PASS",
		"fail-closed effective-privilege audit passed under the gseer_app runtime credential (OD-5)", "", nil)
}

// reportPersonalDBChecks runs the personal-mode doctor checks against
// the configured SQLite file: file presence (WITHOUT creating it —
// doctor is strictly read-only and sqlite.Open would create the file),
// permissions note, read-only migration state, and the same
// index-contents honesty contract as the self-hosted path.
func reportPersonalDBChecks(cmd *cobra.Command, cfg *config.Config, report func(name, outcome, detail, fix string, err error)) {
	if _, serr := os.Stat(cfg.Database.DSN); serr != nil {
		report("personal database", "FAIL", "the personal database file does not exist",
			"gseer setup --personal", serr)
		return
	}
	res, err := sqlite.Open(cfg.Database.DSN)
	if err != nil {
		report("personal database", "FAIL", "cannot open the personal database",
			"gseer setup --personal", err)
		return
	}
	defer func() { _ = res.DB.Close() }()
	detail := res.Path
	if res.PermNote != "" {
		detail += " — " + res.PermNote
	}
	report("personal database", "PASS", detail, "", nil)

	ctx := commandContext(cmd)
	st, merr := sqlite.GetMigrationStatus(ctx, res.DB)
	if merr != nil {
		report("migrations", "FAIL", "cannot read the migration state", "gseer doctor", merr)
		return
	}
	if st.State != sqlite.StateAtHead {
		fix := "re-run: gseer setup --personal"
		if st.State == sqlite.StateDirty {
			fix = "restore a backup (gseer db restore) or recreate the database (gseer setup --personal)"
		}
		report("migrations", "FAIL",
			fmt.Sprintf("schema %s (v%d, head v%d)", st.State, st.Version, st.Head), fix, nil)
		return
	}
	report("migrations", "PASS", fmt.Sprintf("schema at head v%d", st.Head), "", nil)

	meta, qerr := searchlite.New(res.DB).Stats(ctx)
	if qerr != nil {
		report("index", "FAIL", "index query failed", "gseer doctor", qerr)
		return
	}
	reportIndexMeta(meta, report)
	reportDiscoveryFreshness(ctx, res.DB, report)
}

// reportDiscoveryFreshness reports the LOCAL discovery freshness contract
// (personal profile): no sources registered (HINT + the one-command
// bootstrap), or per-source registry state plus the age of the last
// successful collection job.  Discovery is passive-first — the freshness
// line tells the operator HOW CURRENT the Local Index evidence is.
func reportDiscoveryFreshness(ctx context.Context, db *sql.DB, report func(name, outcome, detail, fix string, err error)) {
	store := sqlite.NewStore(db)
	sources, serr := store.ListSources(ctx)
	if serr != nil {
		report("discovery", "FAIL", "cannot read the source registry", "gseer doctor", serr)
		return
	}
	enabled := 0
	for _, s := range sources {
		if s.Enabled {
			enabled++
		}
	}
	if len(sources) == 0 {
		report("discovery", "HINT", "no data sources registered — the index only holds what you collect",
			"gseer setup  (auto-bootstrap: egress context → approved passive sources)", nil)
		return
	}
	var lastRun time.Time
	var lastRunRaw sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT MAX(COALESCE(finished_at, started_at)) FROM collection_jobs WHERE status = 'success'").Scan(&lastRunRaw); err != nil && !errors.Is(err, sql.ErrNoRows) {
		report("discovery", "FAIL", "cannot read the collection job history", "gseer doctor", err)
		return
	}
	// SQLite stores timestamps as TEXT — parse via the storage layer's
	// canonical format (a direct *time.Time scan fails on driver.Value
	// string; the acceptance run caught exactly that).
	if lastRunRaw.Valid && lastRunRaw.String != "" {
		if t, perr := sqlite.ParseTS(lastRunRaw.String); perr == nil {
			lastRun = t
		}
	}
	detail := fmt.Sprintf("%d source(s) registered, %d enabled", len(sources), enabled)
	switch {
	case lastRun.IsZero():
		report("discovery", "HINT", detail+" — no successful collection run yet",
			"gseer collect run --all", nil)
	case time.Since(lastRun) > 14*24*time.Hour:
		report("discovery", "HINT", fmt.Sprintf("%s — last successful run %s (%s old)",
			detail, lastRun.UTC().Format("2006-01-02 15:04 UTC"), time.Since(lastRun).Round(time.Second)),
			"gseer collect run --all  (refresh passive evidence)", nil)
	default:
		report("discovery", "PASS", fmt.Sprintf("%s — last successful run %s (%s old)",
			detail, lastRun.UTC().Format("2006-01-02 15:04 UTC"), time.Since(lastRun).Round(time.Second)), "", nil)
	}
}

// reportIndexMeta renders the shared IndexMeta honesty contract
// (EMPTY hint / fixture label / live counts) for both the PostgreSQL
// and the personal path.
func reportIndexMeta(meta *search.IndexMeta, report func(name, outcome, detail, fix string, err error)) {
	switch {
	case meta.Empty:
		report("index", "HINT", "EMPTY — no assets or services ingested yet",
			"for evaluation data run: gseer setup --load-fixtures", nil)
	case meta.FixtureOnly:
		report("index", "HINT", fmt.Sprintf("contains FIXTURE data — %d assets, %d services, %d observations (SYNTHETIC, not real internet data)",
			meta.Assets, meta.Services, meta.Observations),
			"remove with: gseer setup --purge-fixtures", nil)
	default:
		report("index", "PASS", fmt.Sprintf("%d assets, %d services, %d observations (last observed %s)",
			meta.Assets, meta.Services, meta.Observations, orNever(meta.LastObserved)), "", nil)
	}
}

// reportIndexCheck reports the QS-4 index-contents honesty check:
// EMPTY (HINT with the load pointer), fixture-labeled (HINT with the
// synthetic-data label), or live counts (PASS).
func reportIndexCheck(cmd *cobra.Command, cfg *config.Config, report func(name, outcome, detail, fix string, err error)) {
	ctx := commandContext(cmd)
	pool, err := postgres.NewPool(ctx, cfg.Database.EffectiveDSN())
	if err != nil {
		report("index", "FAIL", "cannot open the index pool", "gseer doctor", err)
		return
	}
	defer pool.Close()
	meta, serr := search.New(pool).Stats(ctx)
	if serr != nil {
		report("index", "FAIL", "index query failed", "gseer db migrate status", serr)
		return
	}
	reportIndexMeta(meta, report)
}

func orNever(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}
