// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// db_command_path_test.go — R4 P0-2 regression battery: the REGISTERED
// public `gseer db backup` / `gseer db restore` commands must run the
// ONE hardened implementation (personal.go runPersonalDBBackup /
// personal_restore.go runPersonalDBRestore), not the retired unsafe
// inline code.  The tests prove the rewiring through PUBLIC BEHAVIOR
// (hardened-only artifacts and refusals), exercise paths with spaces,
// quotes and unusual characters, and cover concurrent backup/restore
// behavior.  These tests mutate package-level seam variables, so they
// must never run in parallel with each other.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// runDBCmd drives the REGISTERED cobra commands (the exact path an
// operator's `gseer db ...` invocation takes through root.go): the full
// argument vector goes through RootCmd, the way the real CLI runs.
func runDBCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Simulate a FRESH process: cobra does not reset flag values between
	// Execute() calls, so a flag set by an earlier in-process invocation
	// would leak into this one.  Every flag of the resolved command is
	// restored to its default and its Changed marker cleared first.
	if cmd, _, ferr := RootCmd.Find(args); ferr == nil {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}
	buf := &bytes.Buffer{}
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs(args)
	err := RootCmd.Execute()
	return buf.String(), err
}

// dbCmdEnv wires a personal config for the db commands and returns its
// path.  The path must be passed as `--config` on EVERY RootCmd
// invocation: Execute() parses the root flags and overwrites
// flags.configPath with the parsed default, so a withConfigPath-only
// assignment does not survive a public-command run (this is exactly how
// a real operator's process resolves the config).
func dbCmdEnv(t *testing.T, livePath string) string {
	t.Helper()
	path := writePersonalConfigForTest(t, livePath)
	withConfigPath(t, path)
	return path
}

// TestDBBackupRestorePublicPathIsHardened proves the registered commands
// run the hardened backends through PUBLIC, hardened-only behavior:
//   - the backup stages + verifies before publish (no staging leftovers);
//   - the restore keeps the previous database as .restore-old;
//   - a SECOND restore never discards that recovery file — it archives
//     it under a unique timestamped name (the old inline implementation
//     silently overwrote it);
//   - no .restore-staging* or .backup-staging* files survive either
//     command.
func TestDBBackupRestorePublicPathIsHardened(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	cfg := dbCmdEnv(t, live)

	out, err := runDBCmd(t, "db", "backup", "--config", cfg, "--out", filepath.Join(dir, "snap.db"))
	if err != nil {
		t.Fatalf("public backup: %v\n%s", err, out)
	}
	if !strings.Contains(out, "verified before publish") {
		t.Errorf("backup output does not reflect the hardened staged publish:\n%s", out)
	}
	if leftovers := stagingLeftoversInDir(dir); len(leftovers) > 0 {
		t.Errorf("staging leftovers after backup: %v", leftovers)
	}

	out, err = runDBCmd(t, "db", "restore", "--config", cfg, filepath.Join(dir, "snap.db"), "--yes")
	if err != nil {
		t.Fatalf("public restore #1: %v\n%s", err, out)
	}
	if _, serr := os.Lstat(live + ".restore-old"); serr != nil {
		t.Errorf("hardened restore must keep .restore-old: %v", serr)
	}
	if leftovers := stagingLeftoversInDir(dir); len(leftovers) > 0 {
		t.Errorf("staging leftovers after restore: %v", leftovers)
	}

	// The second restore archives the existing recovery file instead of
	// overwriting it (hardened-only guarantee).
	out, err = runDBCmd(t, "db", "restore", "--config", cfg, "--from", filepath.Join(dir, "snap.db"), "--yes")
	if err != nil {
		t.Fatalf("public restore #2: %v\n%s", err, out)
	}
	if !strings.Contains(out, "preserved as") {
		t.Errorf("second restore must archive the previous recovery file:\n%s", out)
	}
}

// TestDBBackupRestoreWeirdPaths runs the public backup/restore round-trip
// against destinations containing spaces, single quotes, double quotes,
// parentheses and non-ASCII characters — the parameterized VACUUM INTO
// (no SQL string interpolation) and the plain-copy staging must handle
// all of them; the retired Sprintf form was injectable exactly here.
func TestDBBackupRestoreWeirdPaths(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	cfg := dbCmdEnv(t, live)

	weird := filepath.Join(dir, "dir with space")
	if err := mkdirAllWeird(weird); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A single quote inside the path — the exact character that broke the
	// interpolated `VACUUM INTO '%s'` — plus unicode and brackets.
	snap := filepath.Join(weird, "back'up «لغة» (v1).db")

	out, err := runDBCmd(t, "db", "backup", "--config", cfg, "--out", snap)
	if err != nil {
		t.Fatalf("backup to path with quote/unicode: %v\n%s", err, out)
	}
	if st, serr := os.Stat(snap); serr != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("snapshot missing or wrong mode: %v %v", st, serr)
	}

	// The weird snapshot restores cleanly too.
	out, err = runDBCmd(t, "db", "restore", "--config", cfg, snap, "--yes")
	if err != nil {
		t.Fatalf("restore from weird path: %v\n%s", err, out)
	}
	if hits := fixtureSearchHits(t, live); hits < 1 {
		t.Errorf("restored index lost its fixture content (hits=%d)", hits)
	}
}

// TestDBRestoreRejectsSelfRestoreViaPublicPath pins a refusal the old
// inline implementation did not have: restoring FROM the live database
// itself is a no-op hazard and must be refused before anything is
// staged.  This doubles as public-path proof of the rewiring.
func TestDBRestoreRejectsSelfRestoreViaPublicPath(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	cfg := dbCmdEnv(t, live)

	out, err := runDBCmd(t, "db", "restore", "--config", cfg, live, "--yes")
	if err == nil {
		t.Fatalf("self-restore must be refused (output:\n%s)", out)
	}
	if !strings.Contains(err.Error(), "E_DB_RESTORE") || !strings.Contains(err.Error(), "live database itself") {
		t.Errorf("unexpected self-restore error: %v", err)
	}
	// The live database is untouched and still searchably populated.
	if hits := fixtureSearchHits(t, live); hits < 1 {
		t.Errorf("refused self-restore damaged the live index (hits=%d)", hits)
	}
}

// TestDBBackupNeverOverwritesExistingTarget pins the no-clobber publish:
// a second backup to the same --out is refused, and the existing file is
// byte-identical to what the first backup wrote.
func TestDBBackupNeverOverwritesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	cfg := dbCmdEnv(t, live)
	snap := filepath.Join(dir, "snap.db")
	if _, err := runDBCmd(t, "db", "backup", "--config", cfg, "--out", snap); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	first, err := os.ReadFile(snap)
	if err != nil {
		t.Fatalf("read first snapshot: %v", err)
	}
	// Mutate the live index after the first backup so a buggy overwrite
	// would be observable in the snapshot bytes.
	res, oerr := sqlite.Open(live)
	if oerr != nil {
		t.Fatalf("open live: %v", oerr)
	}
	_, _ = res.DB.Exec("CREATE TABLE IF NOT EXISTS marker_r4(x)")
	_ = res.DB.Close()

	_, err = runDBCmd(t, "db", "backup", "--config", cfg, "--out", snap)
	if err == nil {
		t.Fatal("second backup to an existing target must be refused")
	}
	if !strings.Contains(err.Error(), "E_DB_BACKUP_EXISTS") {
		t.Errorf("unexpected overwrite-refusal error: %v", err)
	}
	second, rerr := os.ReadFile(snap)
	if rerr != nil {
		t.Fatalf("read snapshot after refused backup: %v", rerr)
	}
	if string(first) != string(second) {
		t.Error("the refused backup modified the existing snapshot file")
	}
	if leftovers := stagingLeftoversInDir(dir); len(leftovers) > 0 {
		t.Errorf("staging leftovers after refused backup: %v", leftovers)
	}
}

// TestDBBackupConcurrentSameTarget runs two backups at the SAME --out
// concurrently: exactly one publishes, the other is refused, and the
// published file is a valid database.
func TestDBBackupConcurrentSameTarget(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	_ = dbCmdEnv(t, live)
	snap := filepath.Join(dir, "snap.db")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			cmd := &cobra.Command{Use: "backup"}
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			errs[slot] = runPersonalDBBackup(cmd, snap)
		}(i)
	}
	wg.Wait()

	published, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			published++
		case strings.Contains(err.Error(), "E_DB_BACKUP_EXISTS"):
			refused++
		default:
			t.Fatalf("unexpected concurrent backup error: %v", err)
		}
	}
	if published != 1 || refused != 1 {
		t.Errorf("want exactly one published + one refused backup, got %d/%d", published, refused)
	}
	res, oerr := sqlite.Open(snap)
	if oerr != nil {
		t.Fatalf("published concurrent snapshot is not a valid database: %v", oerr)
	}
	if qerr := quickCheck(res.DB); qerr != nil {
		t.Errorf("published concurrent snapshot failed quick_check: %v", qerr)
	}
	_ = res.DB.Close()
	if leftovers := stagingLeftoversInDir(dir); len(leftovers) > 0 {
		t.Errorf("staging leftovers after concurrent backups: %v", leftovers)
	}
}

// TestDBBackupDuringRestoreStaysConsistent runs a backup WHILE a restore
// is in flight (held inside its staging open by the restoreOpenSrc seam
// until the backup completed).  The backup snapshots the pre-swap state
// through WAL-consistent VACUUM INTO; afterwards the live database must
// open and pass quick_check — no interleaving may corrupt the index.
func TestDBBackupDuringRestoreStaysConsistent(t *testing.T) {
	dir := t.TempDir()
	live := newPopulatedPersonalDB(t, dir, "live.db")
	cfg := dbCmdEnv(t, live)
	snapForRestore := filepath.Join(dir, "restore-source.db")
	backupOut, bprep := runDBCmd(t, "db", "backup", "--config", cfg, "--out", snapForRestore)
	if bprep != nil {
		t.Fatalf("prepare restore source: %v\n%s", bprep, backupOut)
	}
	if _, serr := os.Stat(snapForRestore); serr != nil {
		t.Fatalf("backup claimed success but the snapshot is missing: %v\nbackup output:\n%s", serr, backupOut)
	}

	// Park the restore on its FIRST staged open (the backup probe) until
	// the concurrent backup has finished.  sync.Once guards the single
	// close of the released channel across multiple seam calls.
	release := make(chan struct{})
	released := make(chan struct{})
	var parkOnce sync.Once
	restoreOpenSrc = func(name string) (io.ReadCloser, error) {
		f, oerr := os.Open(name)
		if oerr != nil {
			return nil, oerr
		}
		parkOnce.Do(func() { close(released) })
		<-release
		return f, nil
	}
	t.Cleanup(func() {
		restoreOpenSrc = func(name string) (io.ReadCloser, error) { return os.Open(name) }
	})

	restoreDone := make(chan error, 1)
	go func() {
		_, err := runRestore(t, live, snapForRestore)
		restoreDone <- err
	}()

	// Wait until the restore is actually parked inside the seam (or
	// diagnose immediately when it failed before reaching it), then run
	// the concurrent backup to completion, then release the restore.
	select {
	case <-released:
	case <-time.After(30 * time.Second):
		select {
		case err := <-restoreDone:
			t.Fatalf("restore never reached the staging open: %v", err)
		default:
			t.Fatal("restore never reached the staging open (no early error)")
		}
	}
	backupOut, berr := runDBCmd(t, "db", "backup", "--config", cfg, "--out", filepath.Join(dir, "during-restore.db"))
	close(release)
	if rerr := <-restoreDone; rerr != nil {
		t.Fatalf("restore failed: %v", rerr)
	}
	if berr != nil {
		t.Fatalf("concurrent backup failed: %v\n%s", berr, backupOut)
	}
	res, oerr := sqlite.Open(live)
	if oerr != nil {
		t.Fatalf("live database unusable after concurrent backup+restore: %v", oerr)
	}
	if qerr := quickCheck(res.DB); qerr != nil {
		t.Errorf("live database failed quick_check after concurrent backup+restore: %v", qerr)
	}
	_ = res.DB.Close()
}

// stagingLeftoversInDir lists any leftover staging artifacts in dir.
func stagingLeftoversInDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, ".backup-staging") || strings.Contains(name, ".restore-staging") {
			out = append(out, name)
		}
	}
	return out
}

// mkdirAllWeird creates nested directories (filepath.MkdirAll already
// handles spaces/unicode; the helper documents intent).
func mkdirAllWeird(path string) error {
	return os.MkdirAll(path, 0o700)
}
