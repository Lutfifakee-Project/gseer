// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// personal.go — the Personal Mode backend selector (checkpoint B).
//
// Every personal command runs the SAME GQL chain and the SAME outputs
// as the self-hosted path — only the storage engine differs (one
// embedded SQLite file instead of PostgreSQL).  The self-hosted code
// paths are NOT modified; each command branches on the profile and
// dispatches here.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/fixture"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// loadEngineConfig loads the config accepting the two engine profiles
// (self-hosted PostgreSQL and personal SQLite), with the zero-config
// first run applied (engineConfigOrInit).
func loadEngineConfig() (*config.Config, error) {
	cfg, err := engineConfigOrInit(nil)
	if err != nil {
		return nil, err
	}
	switch cfg.Profile {
	case config.ProfileSelfHosted, config.ProfilePersonal:
		return cfg, nil
	default:
		return nil, fmt.Errorf("E_CONFIG: the engine commands need a local profile (self-hosted or personal; current: %s).\n"+
			"Try: gseer setup  (single-file personal mode)", cfg.Profile)
	}
}

// openPersonal opens the personal database from the config's DSN (the
// database FILE path).
func openPersonal(cfg *config.Config) (*sqlite.OpenResult, error) {
	return sqlite.Open(cfg.Database.DSN)
}

// personalSearchService opens the database and returns the search
// service (per-invocation; the CLI is one-shot).
func personalSearchService(cfg *config.Config) (*searchlite.Service, func(), error) {
	res, err := openPersonal(cfg)
	if err != nil {
		return nil, nil, err
	}
	return searchlite.New(res.DB), func() { _ = res.DB.Close() }, nil
}

// personalStore opens + migrates the personal database and returns the
// store.
func personalStore(ctx context.Context, cfg *config.Config) (*sqlite.Store, *sqlite.OpenResult, error) {
	res, err := openPersonal(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		_ = res.DB.Close()
		return nil, nil, err
	}
	return sqlite.NewStore(res.DB), res, nil
}

// ---------------------------------------------------------------------------
// setup --personal
// ---------------------------------------------------------------------------

// defaultPersonalDBPath is the personal database location:
// $GSEER_HOME/gseer.db when GSEER_HOME is set (an EXPLICIT portable
// install override — respected wherever it points), else the persistent
// XDG state directory ($XDG_STATE_HOME/gseer/gseer.db, falling back to
// $HOME/.local/state/gseer/gseer.db).
//
// FIX (Rev16 personal DB portability): the default used to be
// configDir()/gseer.db — ~/.gseer/gseer.db, or GSEER_HOME/gseer.db for
// portable installs.  When an acceptance harness pointed GSEER_HOME at a
// volatile directory (the /tmp/asdlc-rollback/store.db finding, seeded by
// the v0.3.1-era shared-index acceptance scripts that copied an index
// bundle to $GSEER_HOME/store.db), a tmpfs recycle wiped the database and
// it looked like a corruption.  Without GSEER_HOME the default now lives
// in the XDG state directory — persistent, portable, and structurally
// incapable of resolving under /tmp.  Explicit DSNs (config database.dsn
// or --db-path) are always respected verbatim, and nothing existing is
// ever moved, replaced, or deleted automatically — the legacy location is
// only ever COPIED from (importLegacyPersonalDB below).
func defaultPersonalDBPath() string {
	if v := os.Getenv("GSEER_HOME"); v != "" {
		return filepath.Join(v, "gseer.db")
	}
	return filepath.Join(config.DefaultStateDir(), "gseer.db")
}

// legacyPersonalDBPath is the PRE-Rev16 default location
// (configDir()/gseer.db = ~/.gseer/gseer.db for plain installs).  It is
// used ONLY as the import SOURCE for the safe migration below — never as
// a write target — so an upgraded install keeps every pre-existing
// database byte-identical in place.
func legacyPersonalDBPath() string {
	return filepath.Join(config.DefaultDir(), "gseer.db")
}

// importLegacyPersonalDB safely copies a legacy-default database to the
// new default location, when (and only when):
//   - the caller resolved dbPath from the DEFAULT (not an explicit DSN),
//     and it equals the new default exactly;
//   - the new location does not exist yet (never overwritten);
//   - the legacy location exists as a regular file.
//
// The migration is a COPY followed by a byte-hash verification and an
// atomic rename from a staged temp name in the TARGET directory; the
// legacy source is never modified, moved, or deleted, so the only
// rollback an operator ever needs is "delete the imported copy" (the
// returned note spells that out along with the exact path).  On ANY
// failure the staged copy is removed (inline rollback) and the error is
// returned — a failed import leaves the pre-call state fully intact.
//
// GSEER_HOME installs skip the import: their legacy default and new
// default are the same path, so there is nothing to migrate.
func importLegacyPersonalDB(target string) (imported bool, note string, err error) {
	source := legacyPersonalDBPath()
	if filepath.Clean(source) == filepath.Clean(target) {
		return false, "", nil // GSEER_HOME install: same path, nothing to migrate
	}
	if _, serr := os.Lstat(target); serr == nil {
		return false, "", nil // new location already provisioned — never overwrite
	} else if !errors.Is(serr, os.ErrNotExist) {
		return false, "", fmt.Errorf("cannot inspect the new database location: %w", serr)
	}
	si, serr := os.Lstat(source)
	if serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return false, "", nil // no legacy database — nothing to import
		}
		return false, "", fmt.Errorf("cannot inspect the legacy database %s: %w", source, serr)
	}
	if !si.Mode().IsRegular() {
		return false, "", fmt.Errorf("the legacy database %s is not a regular file — refusing to import (nothing was changed)", source)
	}

	if derr := os.MkdirAll(filepath.Dir(target), 0o700); derr != nil {
		return false, "", fmt.Errorf("cannot create the database state directory: %w", derr)
	}
	staged := target + ".import-staging"
	cleanup := func() { _ = os.Remove(staged) } // inline rollback for every failure path
	if serr := copyFile(source, staged, 0o600); serr != nil {
		cleanup()
		return false, "", fmt.Errorf("importing the legacy database %s: %w", source, serr)
	}
	srcHash, serr := fileHashBytes(source)
	if serr != nil {
		cleanup()
		return false, "", fmt.Errorf("hashing the legacy database for verification: %w", serr)
	}
	dstHash, serr := fileHashBytes(staged)
	if serr != nil {
		cleanup()
		return false, "", fmt.Errorf("hashing the staged copy for verification: %w", serr)
	}
	if srcHash != dstHash {
		cleanup()
		return false, "", fmt.Errorf("the staged copy of %s failed byte verification — import aborted, the original is untouched", source)
	}
	if rerr := os.Rename(staged, target); rerr != nil {
		cleanup()
		return false, "", fmt.Errorf("finalizing the legacy database import: %w", rerr)
	}
	note = fmt.Sprintf("imported your existing personal database from the pre-Rev16 default\n"+
		"         location %s (copy verified byte-identical; the original was NOT\n"+
		"         touched).  To roll back: remove %s and point\n"+
		"         database.dsn in your config back at the original path.", source, target)
	return true, note, nil
}

// volatileDBPathNote returns a short human note when path sits under the
// OS temp directory (tmpfs on most systems: recycled on reboot or by
// periodic cleanup).  It is a WARNING, never an error: an explicit
// override (GSEER_HOME portable install, --db-path, config DSN) is
// respected exactly as given — the note only makes the consequence
// visible so the /tmp/asdlc-rollback finding cannot happen silently.
func volatileDBPathNote(path string) string {
	abs, aerr := filepath.Abs(path)
	if aerr != nil {
		abs = filepath.Clean(path)
	}
	tmp := os.TempDir()
	if tmp == "" {
		return ""
	}
	if abs == tmp || strings.HasPrefix(abs, strings.TrimRight(tmp, string(os.PathSeparator))+string(os.PathSeparator)) {
		return fmt.Sprintf("NOTE: the resolved database path is under the OS temp directory (%s) — "+
			"content there is wiped on reboot/cleanup.  For a persistent install run "+
			"`gseer setup --personal --db-path \"$HOME/.local/state/gseer/gseer.db\"` "+
			"or unset GSEER_HOME.", tmp)
	}
	return ""
}

// fileHashBytes is the raw SHA-256 of a file, shared by the legacy
// import verification.  It streams in chunks (a database can be large;
// the hash must not load it whole) and opens read-only.
func fileHashBytes(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is a resolved database file inside the operator's own state directory, not operator-supplied input
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// runSetupPersonal provisions the personal database: creates the file
// with the SQ-04 permission policy, migrates it, optionally loads the
// labeled fixture corpus, and writes the config.
func runSetupPersonal(cmd *cobra.Command, dbPath string, loadFixtures bool) error {
	out := cmd.OutOrStdout()
	ctx := commandContext(cmd)

	isDefaultPath := dbPath == ""
	if dbPath == "" {
		dbPath = defaultPersonalDBPath()
	}
	if abs, err := filepath.Abs(dbPath); err == nil {
		dbPath = abs
	}

	// FIX (Rev16 portability): the default personal database lives in the
	// persistent XDG state directory (or an explicit GSEER_HOME override);
	// a default resolved from the PRE-Rev16 layout is imported (copied +
	// byte-verified, never moved or deleted) once, and a path under the OS
	// temp dir always earns an explicit warning — the /tmp/asdlc-rollback/
	// store.db finding must be impossible to hit silently.
	if note := volatileDBPathNote(dbPath); note != "" {
		printf(out, "[note ] %s\n", note)
	}
	if isDefaultPath {
		imported, importNote, ierr := importLegacyPersonalDB(dbPath)
		if ierr != nil {
			return fmt.Errorf("E_SETUP: %w", ierr)
		}
		if imported {
			printf(out, "[ ok  ] %s\n", importNote)
		}
	}

	if strings.HasPrefix(dbPath, "postgres://") {
		return fmt.Errorf("E_SETUP_USAGE: --db-path takes a FILE path for personal mode; postgres:// URLs belong to --self-hosted")
	}

	res, err := sqlite.Open(dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = res.DB.Close() }()

	st, err := sqlite.Migrate(ctx, res.DB)
	if err != nil {
		return err
	}
	printf(out, "[ ok  ] personal database: %s\n", res.Path)
	printf(out, "[ ok  ] migrations: schema at head v%d (%s)\n", st.Head, st.State)
	switch res.Mode {
	case sqlite.OpenCreated:
		printf(out, "[ ok  ] new database file created with 0600 permissions\n")
	default:
		if res.PermNote != "" {
			printf(out, "[note ] %s\n", res.PermNote)
		}
	}

	if loadFixtures {
		if err := confirmFixtureAction(cmd, configPersonalScratch(dbPath), "load", "loaded",
			"load the labeled synthetic fixture dataset into the database",
			"7 observations / 6 services / 4 assets (SPEC-04 §9) tagged provenance=fixture",
			"Re-running is idempotent (delivery-identity dedup); the data is NOT real internet data."); err != nil {
			return err
		}
		store := sqlite.NewStore(res.DB)
		stats, err := fixture.Load(ctx, store)
		if err != nil {
			return err
		}
		printf(out, "[ ok  ] fixture source registered (data_sources id=%d, connector=fixture, enabled=false)\n", stats.SourceID)
		printf(out, "[ ok  ] fixtures loaded: %d assets inserted, %d updated; %d services inserted, %d updated; %d observations inserted, %d deduped\n",
			stats.AssetsInserted, stats.AssetsUpdated,
			stats.ServicesInserted, stats.ServicesUpdated,
			stats.ObservationsInserted, stats.ObservationsDeduped)
		printf(out, "\n%s\n", fixture.Banner)
	}

	// Write the config so every following command resolves the profile.
	cfgPath := flags.configPath
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if err := writePersonalConfig(cfgPath, dbPath); err != nil {
		return err
	}
	printf(out, "[ ok  ] config written: %s (profile=personal)\n", cfgPath)

	printf(out, "\nNext:\n")
	printf(out, "  gseer search 'port=443'         — query the index (personal mode)\n")
	printf(out, "  gseer setup --load-fixtures     — load the synthetic evaluation corpus (optional)\n")
	printf(out, "  gseer suppress add ip <ip> --reason \"...\"\n")
	printf(out, "  gseer db backup --out <file>    — consistent backup (VACUUM INTO)\n")
	return nil
}

// configPersonalScratch builds a minimal config for the fixture gate
// (the QS-6 confirmation reads policy.evaluation_fixtures from it).
func configPersonalScratch(dbPath string) *config.Config {
	return &config.Config{
		Profile:  config.ProfilePersonal,
		Database: config.DatabaseConfig{DSN: dbPath},
	}
}

// defaultConfigPath delegates to the config package's platform default —
// the single source of truth the loader resolves (GSEER_HOME-aware).
// v0.3.2 fix: this used to be a private duplicate that WAS GSEER_HOME-aware
// while the loader was not, so `gseer setup --personal` wrote a config the
// loader could not find and every following workflow command failed with
// E_CONFIG_REQUIRED (client.endpoint).
func defaultConfigPath() string {
	return config.DefaultConfigPath()
}

// writePersonalConfig writes the minimal personal config (hand-rolled
// YAML so no unused sections are serialized).
func writePersonalConfig(path string, dbPath string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create the config directory: %w", err)
	}
	body := fmt.Sprintf(`# GSEER personal mode — one embedded SQLite database file.
# Provisioned by: gseer setup --personal
profile: personal

database:
  dsn: %s
`, yamlQuote(dbPath))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("cannot write the config: %w", err)
	}
	return nil
}

// yamlQuote quotes a path for a YAML scalar (single-quote style).
func yamlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ---------------------------------------------------------------------------
// search
// ---------------------------------------------------------------------------

// runPersonalSearch mirrors localSearch with the SQLite service — the
// same renderers, the same facets contract.
func runPersonalSearch(out io.Writer, cfg *config.Config, q search.Query, fr facetsRequest) error {
	budget := 45 * time.Second
	if q.Timeout > 0 {
		budget = q.Timeout + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	svc, closeDB, err := personalSearchService(cfg)
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: cannot open the personal database\nWhy: %v\nTry: gseer setup --personal\n", err)
		exitWith(ExitUnavailable)
		return nil // unreachable in production (exitWith exits); keeps the nil-result fall-through impossible under the test seam
	}
	defer closeDB()

	res, err := svc.Search(ctx, q)
	if err != nil {
		renderSearchError(out, err)
		exitWith(searchExitCode(err))
		return nil
	}
	var fres *search.FacetsResult
	if fr.Enabled {
		fres, err = svc.Facets(ctx, search.FacetsQuery{
			GQL: q.GQL, Mode: q.Mode, Timeout: q.Timeout,
			MaxValues: fr.MaxValues, Facets: fr.Dims,
		})
		if err != nil {
			renderSearchError(out, err)
			exitWith(searchExitCode(err))
			return nil
		}
	}
	renderSearchWithFacets(out, res, fres, flags.output)
	return nil
}

// ---------------------------------------------------------------------------
// suppress
// ---------------------------------------------------------------------------

// runPersonalSuppressAdd mirrors the self-hosted add path (rule +
// retroactive retraction) against the personal store.
func runPersonalSuppressAdd(cmd *cobra.Command, kind suppress.Kind, value, reason, by, expires string, noRetract, jsonOut bool) error {
	cfg, err := loadEngineConfig()
	if err != nil {
		return err
	}
	if cfg.Profile != config.ProfilePersonal {
		return fmt.Errorf("E_PROFILE_MISMATCH: the personal suppress path requires profile=personal")
	}
	in := sqlite.SuppressInput{Kind: kind, Value: value, Reason: reason, CreatedBy: by}
	if expires != "" {
		exp, err := parseSuppressExpiry(expires, time.Now())
		if err != nil {
			return err
		}
		in.ExpiresAt = &exp
	}
	ctx := commandContext(cmd)
	store, res, err := personalStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = res.DB.Close() }()

	rule, existed, err := store.AddSuppression(ctx, in)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if jsonOut {
		if existed {
			return fmt.Errorf("E_SUPPRESS_EXISTS: rule #%d (%s:%s) already exists", rule.ID, rule.Kind, rule.Value)
		}
		_, _ = fmt.Fprintf(out, "{\"id\":%d,\"kind\":%q,\"value\":%q,\"reason\":%q,\"expires_at\":%q}\n",
			rule.ID, rule.Kind, rule.Value, rule.Reason, expires)
		return nil
	}
	if existed {
		printf(out, "Rule already exists: #%d (%s: %s) — nothing changed.\n", rule.ID, rule.Kind, rule.Value)
		return nil
	}
	printf(out, "[ ok  ] suppression rule #%d added: %s = %s\n", rule.ID, rule.Kind, rule.Value)
	if in.ExpiresAt != nil {
		printf(out, "        expires: %s\n", in.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if noRetract {
		println(out, "        retraction skipped (--no-retract); matching records stay until the next retraction")
		return nil
	}
	stats, err := store.RetractSuppressed(ctx, rule)
	if err != nil {
		return fmt.Errorf("E_SUPPRESS_RETRACT: the rule is stored but the retroactive retraction failed.\n"+
			"Why: %v\n"+
			"Try: the rule is already enforcing on ingestion; retry the retraction by re-adding the rule (idempotent)", err)
	}
	printf(out, "[ ok  ] retroactive retraction: %d assets removed, %d services, %d observations (audit rows: %d)\n",
		stats.AssetsRetracted, stats.ServicesRemoved, stats.ObservationsRemoved, stats.AuditRows)
	return nil
}

// runPersonalSuppressList mirrors the self-hosted list path.
func runPersonalSuppressList(cmd *cobra.Command) error {
	cfg, err := loadEngineConfig()
	if err != nil {
		return err
	}
	store, res, err := personalStore(commandContext(cmd), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = res.DB.Close() }()
	rules, err := store.ListSuppressions(cmd.Context())
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(rules) == 0 {
		println(out, "No suppression rules. Add one with: gseer suppress add <kind> <value> --reason \"...\"")
		return nil
	}
	printf(out, "%-6s %-14s %-40s %-10s %-22s %s\n", "ID", "KIND", "VALUE", "ENABLED", "EXPIRES", "REASON")
	for _, r := range rules {
		exp := "never"
		if r.ExpiresAt != nil {
			exp = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		printf(out, "%-6d %-14s %-40s %-10v %-22s %s\n",
			r.ID, r.Kind, r.Value, r.Enabled, exp, r.Reason)
	}
	return nil
}

// runPersonalSuppressRemove mirrors the self-hosted remove path.
func runPersonalSuppressRemove(cmd *cobra.Command, id int64) error {
	cfg, err := loadEngineConfig()
	if err != nil {
		return err
	}
	store, res, err := personalStore(commandContext(cmd), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = res.DB.Close() }()
	removed, err := store.RemoveSuppression(cmd.Context(), id)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if !removed {
		return fmt.Errorf("E_SUPPRESS_NOT_FOUND: rule #%d does not exist — gseer suppress list", id)
	}
	printf(out, "[ ok  ] suppression rule #%d removed.  The audit history is kept; re-ingestion is allowed again.\n", id)
	return nil
}

// ---------------------------------------------------------------------------
// db backup / restore (personal)
// ---------------------------------------------------------------------------

// runPersonalDBBackup performs a consistent, online backup via SQLite's
// VACUUM INTO (one transaction snapshot; the live database is not
// locked out) and restores the 0600 permission policy on the copy.
func runPersonalDBBackup(cmd *cobra.Command, outPath string) error {
	cfg, err := loadEngineConfig()
	if err != nil {
		return err
	}
	if outPath == "" {
		stamp := time.Now().UTC().Format("20060102T150405Z")
		outPath = cfg.Database.DSN + ".backup-" + stamp
	}
	if abs, aerr := filepath.Abs(outPath); aerr == nil {
		outPath = abs
	}
	if outPath == cfg.Database.DSN {
		return fmt.Errorf("E_DB_BACKUP: the backup target must differ from the live database file")
	}

	store, res, err := personalStore(commandContext(cmd), cfg)
	if err != nil {
		return err
	}
	defer func() { _ = res.DB.Close() }()
	// VACUUM INTO produces a consistent snapshot; wal files are not needed.
	if _, err := store.DB.Exec(`VACUUM INTO ?`, sqlite.BuildDSN(outPath)); err != nil {
		// VACUUM INTO takes the raw (non-file:) path in most builds; retry
		// with the plain path when the DSN form is rejected.
		if _, err2 := store.DB.Exec(`VACUUM INTO ?`, outPath); err2 != nil {
			return fmt.Errorf("E_DB_BACKUP: cannot write the backup snapshot: %v / %v", err, err2)
		}
	}
	// Best-effort hardening: VACUUM INTO copies the source file's mode;
	// re-assert 0600 on the snapshot.  chmod is a best-effort no-op on
	// platforms without POSIX mode bits (see open.go isNoChmodOS).
	_ = os.Chmod(outPath, 0o600)
	st, serr := os.Stat(outPath)
	if serr != nil {
		return fmt.Errorf("E_DB_BACKUP: snapshot missing after VACUUM INTO: %w", serr)
	}
	printf(cmd.OutOrStdout(), "[ ok  ] backup written: %s (%d bytes, 0600)\n", outPath, st.Size())
	printf(cmd.OutOrStdout(), "Restore with: gseer db restore %s  (replaces the current database file)\n", outPath)
	return nil
}

// runPersonalDBRestore and copyFile live in personal_restore.go — the
// hardened staged/validated/recoverable-replacement implementation.
