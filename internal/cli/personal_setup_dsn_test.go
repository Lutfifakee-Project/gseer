// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// personal_setup_dsn_test.go — QS-6 R6 regression tests for the setup
// path-override BLOCKER (owner acceptance finding):
//
//	precedence      --db-path flag > explicit config database.dsn > default;
//	legacy import   ONLY on the pure-default resolution;
//	config contract an explicit DSN is never overwritten, and an
//	                existing config is updated surgically (every
//	                operator key and comment preserved);
//	end state       the imported file is byte-identical, or schema+data
//	                identical with only the SQLite journal-mode header
//	                upgrade (verified read-only);
//	volatile /tmp   the warning fires for explicit /tmp targets too.

// writeTestConfig writes a config file and returns its path.  All keys
// used here are part of the loader schema (strict KnownFields decode).
func writeTestConfig(t *testing.T, dir, name, dsn string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "# operator config — hand-maintained\n" +
		"# this comment and every key below MUST survive setup\n" +
		"profile: personal\n\n" +
		"policy:\n  evaluation_fixtures: true\n\n" +
		"log:\n  level: warn\n  format: json\n\n" +
		"database:\n  dsn: '" + dsn + "'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// newPlainPersonalDB creates a schema-head database WITHOUT the SQ-05
// pragmas (plain driver DSN → journal mode DELETE): exactly the shape
// of a pre-Rev16 legacy database, whose header the first rw open then
// upgrades to WAL (the byte diff the owner observed).
func newPlainPersonalDB(t *testing.T, dir, name string) string {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("plain open %s: %v", name, err)
	}
	if _, err := sqlite.Migrate(context.Background(), db); err != nil {
		_ = db.Close()
		t.Fatalf("migrate %s: %v", name, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
	return dbPath
}

// newPlainPersonalDBInto provisions a schema-head, journal-DELETE
// database at an explicit path (helper for the comparator tests).
func newPlainPersonalDBInto(t *testing.T, dbPath string) error {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	if _, err := sqlite.Migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return err
	}
	return db.Close()
}

// TestSetupHonorsExplicitConfigDSN — the QS-6 BLOCKER scenario: a
// config with an explicit database.dsn must be provisioned VERBATIM —
// no default-path DB, no legacy import, config file byte-untouched.
func TestSetupHonorsExplicitConfigDSN(t *testing.T) {
	home := fakeHome(t)
	legacy := newEmptyPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	testDB := filepath.Join(t.TempDir(), "journey", "gseer.db")
	cfgPath := writeTestConfig(t, t.TempDir(), "owner-test.yaml", testDB)
	withConfigPath(t, cfgPath)
	cfgBefore, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	pc := &personalSetupContext{cfgDSN: testDB, cfgSource: cfgPath}
	if err := runSetupPersonal(cmd, "", pc, false); err != nil {
		t.Fatalf("setup --personal with explicit config DSN: %v\noutput:\n%s", err, buf.String())
	}

	if _, serr := os.Stat(testDB); serr != nil {
		t.Errorf("the database must be provisioned exactly at the config DSN %s: %v", testDB, serr)
	}
	if _, serr := os.Stat(defaultPersonalDBPath()); serr == nil {
		t.Errorf("an explicit config DSN must not create the default location %s", defaultPersonalDBPath())
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("an explicit config DSN must not touch the legacy database")
	}
	cfgAfter, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}
	if string(cfgBefore) != string(cfgAfter) {
		t.Errorf("the operator's config must be left byte-identical, got:\n%s", cfgAfter)
	}
	if !strings.Contains(buf.String(), "config left unchanged") {
		t.Errorf("the output must report the unchanged config, got:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "imported your existing personal database") {
		t.Errorf("an explicit config DSN must not trigger the legacy import, got:\n%s", buf.String())
	}

	// Gate 11: status/doctor resolve through the loader — the same file
	// must yield the provisioned DSN.
	cfg, lerr := config.Load(config.Flags{ConfigPath: cfgPath})
	if lerr != nil {
		t.Fatalf("reload config: %v", lerr)
	}
	if cfg.Database.DSN != testDB {
		t.Errorf("status/doctor would open %q, but setup provisioned %s", cfg.Database.DSN, testDB)
	}
}

// TestSetupFlagOverridesConfigDSN — R1 precedence: --db-path outranks
// the config DSN; the config is surgically updated to the flag path
// with every other key and comment preserved.
func TestSetupFlagOverridesConfigDSN(t *testing.T) {
	home := fakeHome(t)
	legacy := newEmptyPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	cfgDSN := filepath.Join(t.TempDir(), "config-dsn.db")
	flagDSN := filepath.Join(t.TempDir(), "flag-dsn.db")
	cfgPath := writeTestConfig(t, t.TempDir(), "config.yaml", cfgDSN)
	withConfigPath(t, cfgPath)

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	pc := &personalSetupContext{cfgDSN: cfgDSN, cfgSource: cfgPath}
	if err := runSetupPersonal(cmd, flagDSN, pc, false); err != nil {
		t.Fatalf("setup --personal --db-path: %v\noutput:\n%s", err, buf.String())
	}

	if _, serr := os.Stat(flagDSN); serr != nil {
		t.Errorf("the flag path must be provisioned verbatim: %v", serr)
	}
	if _, serr := os.Stat(cfgDSN); serr == nil {
		t.Errorf("the overridden config DSN must not be provisioned")
	}
	if _, serr := os.Stat(defaultPersonalDBPath()); serr == nil {
		t.Errorf("neither explicit path is the default — the default location must not exist")
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("an explicit --db-path must not touch the legacy database")
	}

	after, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}
	text := string(after)
	if !strings.Contains(text, "'"+flagDSN+"'") {
		t.Errorf("the config dsn must be updated to the flag path %s, got:\n%s", flagDSN, text)
	}
	if strings.Contains(text, cfgDSN) {
		t.Errorf("the old config DSN must not survive the flag override:\n%s", text)
	}
	for _, keep := range []string{
		"# operator config — hand-maintained",
		"# this comment and every key below MUST survive setup",
		"policy:", "evaluation_fixtures: true",
		"log:", "level: warn", "format: json",
		"profile: personal",
	} {
		if !strings.Contains(text, keep) {
			t.Errorf("the operator's key/comment %q must be preserved, got:\n%s", keep, text)
		}
	}
	if !strings.Contains(buf.String(), "config updated") {
		t.Errorf("the output must report the surgical update, got:\n%s", buf.String())
	}
}

// TestSetupDefaultStillImportsLegacySafely — R2: without any explicit
// DSN the default resolution still imports the legacy database and the
// fresh config is written (pre-existing behavior, now pinned with the
// end-state integrity line).
func TestSetupDefaultStillImportsLegacySafely(t *testing.T) {
	home := fakeHome(t)
	legacy := newEmptyPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	if err := runSetupPersonal(cmd, "", nil, false); err != nil {
		t.Fatalf("setup --personal (default): %v\noutput:\n%s", err, buf.String())
	}

	target := defaultPersonalDBPath()
	if _, serr := os.Stat(target); serr != nil {
		t.Fatalf("the default location must be provisioned: %v", serr)
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("the legacy source must survive byte-identical")
	}
	out := buf.String()
	if !strings.Contains(out, "imported your existing personal database") {
		t.Errorf("the import must be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "end-state integrity") {
		t.Errorf("the end-state integrity proof must be reported, got:\n%s", out)
	}
}

// TestSetupImportEndStateSemanticVerification — R4: a legacy database
// in journal mode DELETE (pre-Rev16 shape) is byte-CHANGED by the
// first rw open (WAL header upgrade) at identical size; setup must
// prove schema+data identity read-only and say so honestly.
func TestSetupImportEndStateSemanticVerification(t *testing.T) {
	home := fakeHome(t)
	legacy := newPlainPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	if err := runSetupPersonal(cmd, "", nil, false); err != nil {
		t.Fatalf("setup --personal (legacy journal=DELETE): %v\noutput:\n%s", err, buf.String())
	}

	target := defaultPersonalDBPath()
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("the legacy source must survive byte-identical")
	}
	if fileHash(t, target) == legacyHash {
		t.Errorf("expected the WAL header upgrade to change the end-state bytes — the semantic branch is not exercised")
	}
	out := buf.String()
	if !strings.Contains(out, "end-state integrity: schema, metadata and row counts identical") {
		t.Errorf("the semantic verification must be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "semantic verification passed") {
		t.Errorf("the semantic verdict must be reported, got:\n%s", out)
	}
	if !strings.Contains(out, "journal-mode header upgrade") {
		t.Errorf("the honest byte-diff explanation must be reported, got:\n%s", out)
	}

	// And prove it independently: both files read-only, semantically equal.
	sdb, err := sqlite.OpenReadOnly(legacy)
	if err != nil {
		t.Fatalf("ro open legacy: %v", err)
	}
	defer func() { _ = sdb.Close() }()
	tdb, err := sqlite.OpenReadOnly(target)
	if err != nil {
		t.Fatalf("ro open target: %v", err)
	}
	defer func() { _ = tdb.Close() }()
	if err := semanticDBEqual(sdb, tdb); err != nil {
		t.Errorf("semantic equality must hold after the import: %v", err)
	}
}

// TestSemanticDBEqualBranches — unit-pins the R4 comparator: equal
// content passes; schema and row-count divergences fail with concrete
// values.
func TestSemanticDBEqualBranches(t *testing.T) {
	t.Run("identical databases", func(t *testing.T) {
		a := newPlainPersonalDB(t, t.TempDir(), "a.db")
		b := newPlainPersonalDB(t, t.TempDir(), "b.db")
		adb, err := sqlite.OpenReadOnly(a)
		if err != nil {
			t.Fatalf("ro open a: %v", err)
		}
		defer func() { _ = adb.Close() }()
		bdb, err := sqlite.OpenReadOnly(b)
		if err != nil {
			t.Fatalf("ro open b: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		if err := semanticDBEqual(adb, bdb); err != nil {
			t.Errorf("two independently provisioned databases must compare equal: %v", err)
		}
	})

	t.Run("row-count divergence", func(t *testing.T) {
		dir := t.TempDir()
		for name, rows := range map[string]int{"a.db": 1, "b.db": 2} {
			db, err := sql.Open("sqlite", filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("open %s: %v", name, err)
			}
			if _, err := sqlite.Migrate(context.Background(), db); err != nil {
				t.Fatalf("migrate %s: %v", name, err)
			}
			if _, err := db.Exec(`CREATE TABLE zz_probe (id INTEGER)`); err != nil {
				t.Fatalf("create probe: %v", err)
			}
			for i := 0; i < rows; i++ {
				if _, err := db.Exec(`INSERT INTO zz_probe (id) VALUES (?)`, i); err != nil {
					t.Fatalf("insert: %v", err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
		}
		adb, err := sqlite.OpenReadOnly(filepath.Join(dir, "a.db"))
		if err != nil {
			t.Fatalf("ro open a: %v", err)
		}
		defer func() { _ = adb.Close() }()
		bdb, err := sqlite.OpenReadOnly(filepath.Join(dir, "b.db"))
		if err != nil {
			t.Fatalf("ro open b: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		err = semanticDBEqual(adb, bdb)
		if err == nil || !strings.Contains(err.Error(), "row counts differ") {
			t.Errorf("a row-count divergence must fail with a concrete report, got: %v", err)
		}
	})

	t.Run("schema divergence", func(t *testing.T) {
		dir := t.TempDir()
		if err := newPlainPersonalDBInto(t, filepath.Join(dir, "a.db")); err != nil {
			t.Fatalf("provision a: %v", err)
		}
		if err := newPlainPersonalDBInto(t, filepath.Join(dir, "b.db")); err != nil {
			t.Fatalf("provision b: %v", err)
		}
		// Make a REAL schema divergence: an extra table on one side.
		bdbW, err := sql.Open("sqlite", filepath.Join(dir, "b.db"))
		if err != nil {
			t.Fatalf("rw open b: %v", err)
		}
		if _, err := bdbW.Exec(`CREATE TABLE zz_probe (id INTEGER)`); err != nil {
			t.Fatalf("create probe: %v", err)
		}
		if err := bdbW.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		adb, err := sqlite.OpenReadOnly(filepath.Join(dir, "a.db"))
		if err != nil {
			t.Fatalf("ro open a: %v", err)
		}
		defer func() { _ = adb.Close() }()
		bdb, err := sqlite.OpenReadOnly(filepath.Join(dir, "b.db"))
		if err != nil {
			t.Fatalf("ro open b: %v", err)
		}
		defer func() { _ = bdb.Close() }()
		err = semanticDBEqual(adb, bdb)
		if err == nil || !strings.Contains(err.Error(), "schema differs") {
			t.Errorf("a schema divergence must fail with a concrete report, got: %v", err)
		}
	})
}

// TestSetupVolatileNoteForExplicitTmpDSN — R1/R5: the /tmp volatility
// warning fires for explicit targets (flag AND config DSN) without
// overriding them.
func TestSetupVolatileNoteForExplicitTmpDSN(t *testing.T) {
	fakeHome(t)
	volatile := filepath.Join(os.TempDir(), "gseer-volatile-test", "gseer.db")
	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	if err := runSetupPersonal(cmd, volatile, nil, false); err != nil {
		t.Fatalf("setup --personal with /tmp --db-path: %v\noutput:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "under the OS temp directory") {
		t.Errorf("the volatile-path warning must appear for a /tmp --db-path, got:\n%s", buf.String())
	}
}

// TestSetupRefusesPostgresConfigDSN — R1: the postgres:// refusal now
// covers the config-DSN surface too.
func TestSetupRefusesPostgresConfigDSN(t *testing.T) {
	fakeHome(t)
	cmd := &cobra.Command{Use: "setup"}
	cmd.SetOut(&bytes.Buffer{})
	pc := &personalSetupContext{cfgDSN: "postgres://operator:secret@127.0.0.1:5432/gseer"}
	err := runSetupPersonal(cmd, "", pc, false)
	if err == nil {
		t.Fatal("a postgres:// database.dsn must be refused (SQLite-only)")
	}
	if !strings.Contains(err.Error(), "E_SETUP_USAGE") || !strings.Contains(err.Error(), "database.dsn (config)") {
		t.Errorf("unexpected refusal: %v", err)
	}
}

// TestSetupZeroConfigHonorsDBPath — audit gate 12 finding: on a FRESH
// machine (no config anywhere) plain `setup --db-path X` must
// provision at X instead of silently ignoring the flag.
func TestSetupZeroConfigHonorsDBPath(t *testing.T) {
	home := fakeHome(t)
	flagDSN := filepath.Join(t.TempDir(), "fresh-path.db")

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	o := setupOptions{personal: false, personalDBPath: flagDSN, offline: true}
	if err := runSetupProfileDispatch(cmd, o); err != nil {
		t.Fatalf("fresh-machine setup --db-path: %v\noutput:\n%s", err, buf.String())
	}

	if _, serr := os.Stat(flagDSN); serr != nil {
		t.Errorf("the fresh-machine --db-path must be provisioned verbatim: %v", serr)
	}
	if _, serr := os.Stat(defaultPersonalDBPath()); serr == nil {
		t.Errorf("an explicit --db-path on a fresh machine must not create the default location")
	}
	cfgBytes, rerr := os.ReadFile(filepath.Join(home, ".gseer", "config.yaml"))
	if rerr != nil {
		t.Fatalf("the fresh config must be written: %v", rerr)
	}
	if !strings.Contains(string(cfgBytes), flagDSN) {
		t.Errorf("the fresh config must carry the flag path, got:\n%s", cfgBytes)
	}
}

// TestUpsertPersonalConfigShapes — R3 unit pins for the surgical
// config writer: replace-in-place, insert-into-block, append-block,
// prepend-profile — every other line byte-identical.
func TestUpsertPersonalConfigShapes(t *testing.T) {
	t.Run("replace existing dsn and profile", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTestConfig(t, dir, "config.yaml", "/old/path.db")
		if err := upsertPersonalConfig(path, "/new/path.db"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		after, _ := os.ReadFile(path)
		text := string(after)
		if !strings.Contains(text, "'/new/path.db'") || strings.Contains(text, "/old/path.db") {
			t.Errorf("dsn must be replaced in place, got:\n%s", text)
		}
		for _, keep := range []string{"# operator config — hand-maintained", "evaluation_fixtures: true", "level: warn", "format: json"} {
			if !strings.Contains(text, keep) {
				t.Errorf("%q must survive, got:\n%s", keep, text)
			}
		}
		if strings.Count(text, "profile: personal") != 1 {
			t.Errorf("exactly one profile line expected, got:\n%s", text)
		}
	})

	t.Run("database block without dsn", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		body := "profile: personal\npolicy:\n  evaluation_fixtures: true\n\ndatabase:\n  host: ignored\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := upsertPersonalConfig(path, "/p/x.db"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		text, _ := os.ReadFile(path)
		s := string(text)
		if !strings.Contains(s, "database:\n  dsn: '/p/x.db'\n  host: ignored") {
			t.Errorf("dsn must be inserted right after the database header, got:\n%s", s)
		}
	})

	t.Run("no database block at all", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte("profile: personal\nlog:\n  level: info\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := upsertPersonalConfig(path, "/p/y.db"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		text, _ := os.ReadFile(path)
		s := string(text)
		if !strings.Contains(s, "\ndatabase:\n  dsn: '/p/y.db'") {
			t.Errorf("a database block must be appended, got:\n%s", s)
		}
	})

	t.Run("missing profile is prepended", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte("log:\n  level: info\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := upsertPersonalConfig(path, "/p/z.db"); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		text, _ := os.ReadFile(path)
		if !strings.HasPrefix(string(text), "profile: personal\n") {
			t.Errorf("profile must be prepended, got:\n%s", text)
		}
	})

	t.Run("upserted config still loads", func(t *testing.T) {
		dir := t.TempDir()
		path := writeTestConfig(t, dir, "config.yaml", "/old.db")
		if err := upsertPersonalConfig(path, filepath.Join(dir, "new.db")); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		cfg, err := config.Load(config.Flags{ConfigPath: path})
		if err != nil {
			t.Fatalf("the surgically updated config must still load: %v", err)
		}
		if cfg.Database.DSN != filepath.Join(dir, "new.db") {
			t.Errorf("loader must see the new dsn, got %q", cfg.Database.DSN)
		}
	})
}
