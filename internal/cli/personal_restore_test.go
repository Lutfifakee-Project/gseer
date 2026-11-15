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

// personal_restore_test.go — regression battery for the hardened
// personal-mode `db restore` (recoverable replacement).  Failure
// injection is deterministic through the package's I/O seams (see
// personal_restore.go) — no fake filesystems, no permission tricks
// that misbehave under root.  These tests mutate package-level seam
// variables, so they must never run in parallel.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/fixture"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// runRestore drives runPersonalDBRestore the way the cobra command
// does: a personal config at flags.configPath, a captured output
// buffer, --yes consent.  Returns the output and the error.
func runRestore(t *testing.T, livePath, backupPath string) (string, error) {
	t.Helper()
	withConfigPath(t, writePersonalConfigForTest(t, livePath))
	cmd := &cobra.Command{Use: "restore"}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	err := runPersonalDBRestore(cmd, backupPath, true)
	return out.String(), err
}

// newPopulatedPersonalDB provisions a migrated personal database and
// loads the labeled synthetic fixture corpus — the content a restore
// must bring back searchably.
func newPopulatedPersonalDB(t *testing.T, dir, name string) string {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		_ = res.DB.Close()
		t.Fatalf("migrate %s: %v", name, err)
	}
	if _, err := fixture.Load(context.Background(), sqlite.NewStore(res.DB)); err != nil {
		_ = res.DB.Close()
		t.Fatalf("load fixtures into %s: %v", name, err)
	}
	if err := res.DB.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
	return dbPath
}

// newEmptyPersonalDB provisions a migrated database with an EMPTY
// index (no fixtures) — the "old" live state a restore replaces.
func newEmptyPersonalDB(t *testing.T, dir, name string) string {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		_ = res.DB.Close()
		t.Fatalf("migrate %s: %v", name, err)
	}
	if err := res.DB.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
	return dbPath
}

// fixtureSearchHits runs the real GQL engine against the database at
// dbPath and returns how many rows the fixture query matches.
func fixtureSearchHits(t *testing.T, dbPath string) int {
	t.Helper()
	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open for search: %v", err)
	}
	defer func() { _ = res.DB.Close() }()
	out, err := searchlite.New(res.DB).Search(context.Background(), search.Query{
		GQL: `port==443 && title CONTAINS "login"`,
	})
	if err != nil {
		t.Fatalf("search after restore: %v", err)
	}
	return len(out.Rows)
}

func fileHash(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func assertNoStagingLeft(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		entries, rerr := os.ReadDir(dir)
		if rerr != nil {
			continue
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".restore-staging") {
				t.Errorf("staging leftover in %s: %s", dir, e.Name())
			}
		}
	}
}

// errReadCloser fails the copy after n delivered bytes — a
// deterministic mid-stream copy failure (disk-full / EIO analogue).
type errReadCloser struct {
	r io.Reader
	n int
}

func (e *errReadCloser) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, errors.New("injected read failure")
	}
	if len(p) > e.n {
		p = p[:e.n]
	}
	n, _ := e.r.Read(p)
	e.n -= n
	if e.n <= 0 {
		return n, errors.New("injected read failure")
	}
	return n, nil
}

func (e *errReadCloser) Close() error { return nil }

// ---------------------------------------------------------------------------
// 1. success — restore and REAL search after restore
// ---------------------------------------------------------------------------

func TestRestoreSuccessAndSearchAfterRestore(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")

	if got := fixtureSearchHits(t, live); got != 0 {
		t.Fatalf("pre-restore search hits = %d, want 0 (empty index)", got)
	}

	out, err := runRestore(t, live, backup)
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	for _, want := range []string{"restored", "recoverable replacement", "previous database is kept at"} {
		if !strings.Contains(out, want) {
			t.Errorf("restore output missing %q:\n%s", want, out)
		}
	}

	// The restored database is searchable through the real engine,
	// and carries the BACKUP's data, not the old live state.
	if got := fixtureSearchHits(t, live); got != 1 {
		t.Errorf("search after restore hits = %d, want 1", got)
	}

	// The previous live database is preserved aside.
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Errorf("recovery file missing: %v", serr)
	}
	// The restored file carries the restrictive permission policy.
	if runtime.GOOS != "windows" {
		if st, serr := os.Stat(live); serr != nil {
			t.Errorf("stat live: %v", serr)
		} else if perm := st.Mode().Perm(); perm != 0o600 {
			t.Errorf("restored live mode = %04o, want 0600", perm)
		}
	}
	assertNoStagingLeft(t, dir)
}

// ---------------------------------------------------------------------------
// 2/3. missing backup, invalid backup
// ---------------------------------------------------------------------------

func TestRestoreMissingBackupFile(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	before := fileHash(t, live)

	_, err := runRestore(t, live, filepath.Join(dir, "does-not-exist.db"))
	if err == nil || !strings.Contains(err.Error(), "E_DB_RESTORE") || !strings.Contains(err.Error(), "backup file not found") {
		t.Fatalf("error = %v, want E_DB_RESTORE backup file not found", err)
	}
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed after a refused restore")
	}
	assertNoStagingLeft(t, dir)
}

func TestRestoreInvalidBackupRejected(t *testing.T) {
	t.Run("not a database at all", func(t *testing.T) {
		dir := t.TempDir()
		live := newEmptyPersonalDB(t, dir, "gseer.db")
		backup := filepath.Join(dir, "backup.db")
		if werr := os.WriteFile(backup, []byte("this is definitely not a SQLite database"), 0o600); werr != nil {
			t.Fatalf("write garbage backup: %v", werr)
		}
		before := fileHash(t, live)

		_, err := runRestore(t, live, backup)
		if err == nil || !strings.Contains(err.Error(), "E_DB_RESTORE") {
			t.Fatalf("error = %v, want E_DB_RESTORE refusal", err)
		}
		if after := fileHash(t, live); after != before {
			t.Errorf("live database was touched by a refused restore")
		}
		assertNoStagingLeft(t, dir)
	})

	t.Run("truncated real database fails integrity check", func(t *testing.T) {
		dir := t.TempDir()
		live := newEmptyPersonalDB(t, dir, "gseer.db")
		full := newPopulatedPersonalDB(t, dir, "full.db")
		raw, rerr := os.ReadFile(full)
		if rerr != nil {
			t.Fatalf("read full db: %v", rerr)
		}
		if len(raw) < 8192 {
			t.Fatalf("fixture db unexpectedly small (%d bytes); cannot truncate", len(raw))
		}
		backup := filepath.Join(dir, "truncated.db")
		if werr := os.WriteFile(backup, raw[:len(raw)/2], 0o600); werr != nil {
			t.Fatalf("write truncated backup: %v", werr)
		}
		before := fileHash(t, live)

		_, err := runRestore(t, live, backup)
		if err == nil || !strings.Contains(err.Error(), "E_DB_RESTORE") {
			t.Fatalf("error = %v, want E_DB_RESTORE refusal", err)
		}
		if !strings.Contains(err.Error(), "integrity check") && !strings.Contains(err.Error(), "not a valid") {
			t.Errorf("error should name the integrity/validation stage, got: %v", err)
		}
		if after := fileHash(t, live); after != before {
			t.Errorf("live database was touched by a refused restore")
		}
		assertNoStagingLeft(t, dir)
	})
}

// ---------------------------------------------------------------------------
// 4/5/6. copy failure, sync failure, close failure (injected)
// ---------------------------------------------------------------------------

func TestRestoreCopyFailureInjection(t *testing.T) {
	t.Run("source open fails", func(t *testing.T) {
		dir := t.TempDir()
		live := newEmptyPersonalDB(t, dir, "gseer.db")
		backup := newPopulatedPersonalDB(t, dir, "backup.db")
		before := fileHash(t, live)

		orig := restoreOpenSrc
		restoreOpenSrc = func(string) (io.ReadCloser, error) { return nil, errors.New("injected open failure") }
		t.Cleanup(func() { restoreOpenSrc = orig })

		_, err := runRestore(t, live, backup)
		if err == nil || !strings.Contains(err.Error(), "cannot stage the backup copy") {
			t.Fatalf("error = %v, want a staging failure", err)
		}
		if !strings.Contains(err.Error(), "the live database was not touched") {
			t.Errorf("error must state the live database was untouched, got: %v", err)
		}
		if after := fileHash(t, live); after != before {
			t.Errorf("live database changed on a staging failure")
		}
		assertNoStagingLeft(t, dir)
	})

	t.Run("mid-copy read failure", func(t *testing.T) {
		dir := t.TempDir()
		live := newEmptyPersonalDB(t, dir, "gseer.db")
		backup := newPopulatedPersonalDB(t, dir, "backup.db")
		before := fileHash(t, live)
		raw, rerr := os.ReadFile(backup)
		if rerr != nil {
			t.Fatalf("read backup: %v", rerr)
		}

		orig := restoreOpenSrc
		restoreOpenSrc = func(string) (io.ReadCloser, error) {
			return &errReadCloser{r: bytes.NewReader(raw), n: 128}, nil
		}
		t.Cleanup(func() { restoreOpenSrc = orig })

		_, err := runRestore(t, live, backup)
		if err == nil || !strings.Contains(err.Error(), "cannot stage the backup copy") {
			t.Fatalf("error = %v, want a staging failure", err)
		}
		if after := fileHash(t, live); after != before {
			t.Errorf("live database changed on a staging failure")
		}
		assertNoStagingLeft(t, dir) // the partial copy must be cleaned up
	})
}

func TestRestoreSyncFailureInjection(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	orig := restoreSyncFile
	restoreSyncFile = func(*os.File) error { return errors.New("injected fsync failure") }
	t.Cleanup(func() { restoreSyncFile = orig })

	_, err := runRestore(t, live, backup)
	if err == nil || !strings.Contains(err.Error(), "cannot stage the backup copy") {
		t.Fatalf("error = %v, want a staging failure naming the fsync path", err)
	}
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a staging failure")
	}
	assertNoStagingLeft(t, dir)
}

func TestRestoreCloseFailureInjection(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	orig := restoreCloseFile
	restoreCloseFile = func(*os.File) error { return errors.New("injected close failure") }
	t.Cleanup(func() { restoreCloseFile = orig })

	_, err := runRestore(t, live, backup)
	if err == nil || !strings.Contains(err.Error(), "cannot stage the backup copy") {
		t.Fatalf("error = %v, want a staging failure naming the close path", err)
	}
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a staging failure")
	}
	assertNoStagingLeft(t, dir)
	// Regression (Windows CI run 43137495295): the injected close
	// failure used to leave the staging HANDLE open — os.Remove then
	// failed with a sharing violation, silently leaving a partial
	// staging file whose open handle ALSO broke the test framework's
	// t.TempDir cleanup ("The process cannot access the file because
	// it is being used by another process").  After every injected
	// failure the directory must be fully removable: no leaked handle
	// may outlive the failed restore.
	if rerr := os.RemoveAll(dir); rerr != nil {
		t.Errorf("temp directory not removable after the injected close failure (an open handle leaked): %v", rerr)
	}
}

// ---------------------------------------------------------------------------
// FIX ROUND 3 + 4: bounded sync waits and watchdog completeness.  A
// wedged storage layer (journal commit that never completes, NFS
// server gone, failing disk) used to hang the CLI forever at one of
// the unbounded sync points (owner-side evidence: K2 of
// scripts/v032-acceptance.sh hung >22 minutes, threads parked in
// futex/wait_woken, no output, no error).  These tests pin the
// contract: every durability wait (staged fsync, staged-copy file
// close, EVERY sql.DB close on every path, directory fsync) is
// bounded; a wedge is an EXPLICIT typed error; the sync itself is
// never skipped; a timed-out operation never leads to a second
// blocking close; a new restore FAILS CLOSED while an operation is
// still outstanding and self-heals once it drains; no wedge path
// prints a false success; the live database and the recovery file
// stay consistent; and no operation left behind after the cleanup can
// damage or resurrect any file once the wedge resolves.
// ---------------------------------------------------------------------------

// shrinkSyncTimeout shrinks the watchdog bound for the test.  It
// returns the release channel the seam closures block on and an
// unwedge function (once-guarded: safe to call from the test body AND
// from the cleanup).  The cleanup unwedges and then DRAINS the
// outstanding-wedge registry, so a later test never runs with a stale
// fail-closed state from this one.
func shrinkSyncTimeout(t *testing.T) (chan struct{}, func()) {
	t.Helper()
	orig := restoreSyncTimeout
	restoreSyncTimeout = 250 * time.Millisecond
	t.Cleanup(func() { restoreSyncTimeout = orig })
	release := make(chan struct{})
	var once sync.Once
	unwedge := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		unwedge()
		drainRestoreWedge(t)
	})
	return release, unwedge
}

// drainRestoreWedge waits until no restore sync operation is
// outstanding anymore (restoreWedgeOutstanding back to zero).
func drainRestoreWedge(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for restoreWedgeOutstanding.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("outstanding restore wedge operations did not drain: %d", restoreWedgeOutstanding.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRestoreBoundedSyncPassesThrough(t *testing.T) {
	if err := restoreBoundedSync("probe", func() error { return nil }); err != nil {
		t.Fatalf("a healthy sync must pass through untouched: %v", err)
	}
	want := errors.New("boom")
	if err := restoreBoundedSync("probe", func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("a failed sync must surface verbatim (errors.Is), got %v", err)
	}
	if n := restoreWedgeOutstanding.Load(); n != 0 {
		t.Fatalf("a completing sync must never register as outstanding (got %d)", n)
	}
}

func TestRestoreBoundedSyncExpiresWithTypedError(t *testing.T) {
	release, _ := shrinkSyncTimeout(t)
	// run() only unblocks when the cleanup unwedges (after the test
	// body) — waiting for it here would self-deadlock the test, so the
	// goroutine is simply left to finish on its own (the buffered
	// result channel makes that leak-safe).
	err := restoreBoundedSync("the probe sync", func() error {
		<-release
		return nil
	})
	if err == nil || !errors.Is(err, errRestoreSyncStuck) {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK (errors.Is errRestoreSyncStuck)", err)
	}
	if !strings.Contains(err.Error(), "E_DB_RESTORE_SYNC_STUCK") ||
		!strings.Contains(err.Error(), "the probe sync") ||
		!strings.Contains(err.Error(), "DURABILITY IS UNCONFIRMED") {
		t.Fatalf("error must name the code, the stuck operation and the durability terms, got: %v", err)
	}
	if n := restoreWedgeOutstanding.Load(); n != 1 {
		t.Fatalf("a timed-out operation must register exactly one outstanding wedge (got %d)", n)
	}
}

// noFalseSuccess is the FIX ROUND 4 no-false-success assertion shared
// by every wedge test: none of the wedge paths may print the success
// line.
func noFalseSuccess(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "[ ok  ] restored") {
		t.Errorf("a wedged restore must never print the success line, got: %s", out)
	}
}

func TestRestoreStuckStagedFileSyncReportsExplicitly(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreSyncFile
	restoreSyncFile = func(*os.File) error { <-release; return nil }
	t.Cleanup(func() { restoreSyncFile = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "fsync of the staged copy") {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK naming the staged-copy fsync", err)
	}
	noFalseSuccess(t, out)
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a wedged staging fsync")
	}
	assertNoStagingLeft(t, dir)

	// FIX ROUND 4: un-wedge and prove the outstanding operation does
	// NO damage afterwards — the fsync keeps working on the unlinked
	// inode: no staging file may reappear and the live database stays
	// byte-identical.
	unwedge()
	drainRestoreWedge(t)
	assertNoStagingLeft(t, dir)
	if after := fileHash(t, live); after != before {
		t.Errorf("the released wedged fsync changed the live database")
	}
}

func TestRestoreStuckDirectorySyncReportsExplicitlyAfterSwap(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	wantHash := fileHash(t, backup) // the content the restore installs

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreSyncDir
	restoreSyncDir = func(string) error { <-release; return nil }
	t.Cleanup(func() { restoreSyncDir = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "E_DB_RESTORE_DIRSYNC") {
		t.Fatalf("error = %v, want E_DB_RESTORE_DIRSYNC wrapping E_DB_RESTORE_SYNC_STUCK", err)
	}
	// The "[ ok ] restored" line prints only AFTER the directory sync —
	// a wedged dir sync must NOT claim success, only state the swap is
	// in place with durability unconfirmed (honest terms).
	noFalseSuccess(t, out)
	if !strings.Contains(err.Error(), "the restore IS in place") {
		t.Errorf("error must state the restore is in place, got: %v", err)
	}
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("after the swap the live database must hold the restored content")
	}
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Errorf("the recovery copy must exist after a successful swap: %v", serr)
	}
	assertNoStagingLeft(t, dir)

	// FIX ROUND 4: once the wedged dir fsync drains, nothing may change
	// — the deferred fsync only flushes directory metadata of the
	// already-completed renames; the live database, the recovery file
	// and the clean directory must all be exactly as reported.
	unwedge()
	drainRestoreWedge(t)
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("the released wedged dir fsync changed the live database")
	}
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Errorf("the recovery copy must survive the released wedge: %v", serr)
	}
	assertNoStagingLeft(t, dir)
}

func TestRestoreStuckStagingCloseReportsExplicitly(t *testing.T) {
	// The staging close runs the driver's checkpoint + fsync — the same
	// bounded-sync contract, wedged through the restoreCloseDB seam
	// (deterministic, like every other seam in this file).  FIX ROUND
	// 4: the seam wedges ONLY the validated staging close (the second
	// sql.DB close of the restore); the probe close (the first one) is
	// bounded separately and passes through here.
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreCloseDB
	var closeCalls atomic.Int64
	restoreCloseDB = func(db *sql.DB) error {
		if closeCalls.Add(1) >= 2 { // call 1 = probe close, call 2 = validated staging close
			<-release
		}
		return db.Close()
	}
	t.Cleanup(func() { restoreCloseDB = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "close of the validated staging copy") {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK naming the staging close", err)
	}
	noFalseSuccess(t, out)
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a wedged staging close")
	}
	assertNoStagingLeft(t, dir)

	// FIX ROUND 4: after the wedge resolves, the deferred close runs
	// its real checkpoint against the UNLINKED staging inode and its
	// by-name sidecar cleanup finds nothing — nothing may be
	// resurrected and the live database must stay byte-identical.
	unwedge()
	drainRestoreWedge(t)
	assertNoStagingLeft(t, dir)
	if after := fileHash(t, live); after != before {
		t.Errorf("the released wedged staging close changed the live database")
	}
}

func TestRestoreStuckCloseAfterFailedIntegrityCheck(t *testing.T) {
	// FIX ROUND 4 (audit item 1, every path): the close after a FAILED
	// integrity check is bounded too — a real connection exists there
	// (quickCheck just ran), so its close-time checkpoint+fsync is
	// exactly the wedge class from the owner's evidence.  The corrupt
	// backup follows the truncated-database technique of
	// TestRestoreInvalidBackupRejected.
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	full := newPopulatedPersonalDB(t, dir, "full.db")
	raw, rerr := os.ReadFile(full)
	if rerr != nil {
		t.Fatalf("read full db: %v", rerr)
	}
	if len(raw) < 8192 {
		t.Fatalf("fixture db unexpectedly small (%d bytes); cannot truncate", len(raw))
	}
	backup := filepath.Join(dir, "truncated.db")
	if werr := os.WriteFile(backup, raw[:len(raw)/2], 0o600); werr != nil {
		t.Fatalf("write truncated backup: %v", werr)
	}
	before := fileHash(t, live)

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreCloseDB
	var closeCalls atomic.Int64
	restoreCloseDB = func(db *sql.DB) error {
		if closeCalls.Add(1) >= 2 { // call 1 = probe close (passes), call 2 = post-integrity-failure close (wedges)
			<-release
		}
		return db.Close()
	}
	t.Cleanup(func() { restoreCloseDB = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "close of the staged copy after a failed integrity check") {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK naming the post-integrity-failure close", err)
	}
	if !strings.Contains(err.Error(), "integrity check") {
		t.Errorf("the integrity failure must stay the primary failure, got: %v", err)
	}
	noFalseSuccess(t, out)
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a wedged post-integrity-failure close")
	}
	assertNoStagingLeft(t, dir)

	unwedge()
	drainRestoreWedge(t)
	assertNoStagingLeft(t, dir)
	if after := fileHash(t, live); after != before {
		t.Errorf("the released wedged close changed the live database")
	}
}

func TestRestoreStuckProbeCloseReportsExplicitly(t *testing.T) {
	// FIX ROUND 4 (audit item 1): even the probe close is bounded —
	// trivial today (the lazy opener holds no connection) but
	// mechanically guaranteed.  Wedge the FIRST sql.DB close.
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreCloseDB
	var closeCalls atomic.Int64
	restoreCloseDB = func(db *sql.DB) error {
		if closeCalls.Add(1) == 1 { // call 1 = the backup probe close
			<-release
		}
		return db.Close()
	}
	t.Cleanup(func() { restoreCloseDB = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "close of the backup probe") {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK naming the probe close", err)
	}
	noFalseSuccess(t, out)
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a wedged probe close")
	}
	// The restore aborted before any staging file was created.
	assertNoStagingLeft(t, dir)

	unwedge()
	drainRestoreWedge(t)
	assertNoStagingLeft(t, dir)
	if after := fileHash(t, live); after != before {
		t.Errorf("the released wedged probe close changed the live database")
	}
}

func TestRestoreStuckStagedCopyCloseReportsExplicitly(t *testing.T) {
	// FIX ROUND 4 (audit item 2): the staged-copy FILE close after the
	// fsync is bounded too — close(2) with an fsync in flight can
	// block (NFS writeback), so the wedge must surface as an explicit
	// error and the cleanup must NOT attempt a second close (os.File
	// serializes closes; it would hang behind the wedged one).
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreCloseFile
	restoreCloseFile = func(*os.File) error { <-release; return nil }
	t.Cleanup(func() { restoreCloseFile = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !errors.Is(err, errRestoreSyncStuck) || !strings.Contains(err.Error(), "close of the staged copy") {
		t.Fatalf("error = %v, want E_DB_RESTORE_SYNC_STUCK naming the staged-copy close", err)
	}
	noFalseSuccess(t, out)
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a wedged staged-copy close")
	}
	assertNoStagingLeft(t, dir)

	unwedge()
	drainRestoreWedge(t)
	assertNoStagingLeft(t, dir)
	if after := fileHash(t, live); after != before {
		t.Errorf("the released wedged staged-copy close changed the live database")
	}
}

func TestRestoreSecondRestoreFailsClosedWhileWedgeOutstanding(t *testing.T) {
	// FIX ROUND 4 fail-closed policy: while a previous restore's sync
	// is still outstanding on wedged storage, a SECOND restore in the
	// same process is refused (its staging path could collide with the
	// deferred checkpoint / by-name sidecar cleanup of the outstanding
	// close).  Once the wedge drains, restores work again (self-heal).
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	wantHash := fileHash(t, backup) // the content the restore installs

	release, unwedge := shrinkSyncTimeout(t)
	orig := restoreSyncDir
	restoreSyncDir = func(string) error { <-release; return nil }
	t.Cleanup(func() { restoreSyncDir = orig })

	// Restore 1 wedges at the directory fsync, AFTER the swap.
	out1, err1 := runRestore(t, live, backup)
	if err1 == nil || !errors.Is(err1, errRestoreSyncStuck) || !strings.Contains(err1.Error(), "E_DB_RESTORE_DIRSYNC") {
		t.Fatalf("restore 1: error = %v, want E_DB_RESTORE_DIRSYNC", err1)
	}
	noFalseSuccess(t, out1)
	if n := restoreWedgeOutstanding.Load(); n != 1 {
		t.Fatalf("after restore 1 the wedge registry must hold exactly 1 outstanding operation (got %d)", n)
	}

	// Restore 2, same process, wedge still outstanding: refused BEFORE
	// anything is staged or replaced.
	out2, err2 := runRestore(t, live, backup)
	if err2 == nil || !strings.Contains(err2.Error(), "E_DB_RESTORE_INFLIGHT") {
		t.Fatalf("restore 2: error = %v, want E_DB_RESTORE_INFLIGHT (fail-closed)", err2)
	}
	noFalseSuccess(t, out2)
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("the refused restore must not touch the live database")
	}
	assertNoStagingLeft(t, dir)

	// The wedge drains when storage recovers — the policy self-heals.
	unwedge()
	drainRestoreWedge(t)

	out3, err3 := runRestore(t, live, backup)
	if err3 != nil {
		t.Fatalf("restore 3 after the wedge drained must succeed: %v", err3)
	}
	if !strings.Contains(out3, "[ ok  ] restored") {
		t.Errorf("restore 3 must print the success line, got: %s", out3)
	}
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("restore 3 must leave the restored content in place")
	}
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Errorf("restore 3 must keep a recovery copy (the previous one is archived, never discarded): %v", serr)
	}
	assertNoStagingLeft(t, dir)
}

// dirListing returns the sorted names of the entries directly inside
// dir (one level) — used to prove a refused restore adds and removes
// NOTHING from the database's directory.
func dirListing(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestRestoreConcurrentEntryRefusedWithoutBlocking(t *testing.T) {
	// FIX ROUND 5: the entry guard is exclusive and NON-BLOCKING.
	// Restore A is parked at an injectable operation (the staged fsync)
	// while holding the guard; restore B must fail IMMEDIATELY with
	// E_DB_RESTORE_INFLIGHT while A is still executing — B RETURNS
	// before releaseA is closed, which is the deterministic proof of
	// non-blocking (a blocking guard would deadlock the test right
	// there).  B creates no staging artifacts and does not touch the
	// live database.  Once A is released it completes normally, and a
	// later restore succeeds again.
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)
	wantHash := fileHash(t, backup) // the content the restore installs

	// The config is written and installed ONCE, before any concurrency:
	// flags.configPath is shared package state and must never be
	// written from two goroutines.  The invocations below build their
	// own cobra commands and output buffers — no other shared state.
	cfgPath := writePersonalConfigForTest(t, live)
	oldCfg := flags.configPath
	flags.configPath = cfgPath
	t.Cleanup(func() { flags.configPath = oldCfg })

	// A parks at the staged fsync and signals exactly when it is there:
	// at that point A has already acquired the entry guard.  ONLY the
	// first fsync invocation (restore A) parks; later invocations (the
	// final restore) pass through to the real Sync.
	enteredA := make(chan struct{})
	releaseA := make(chan struct{})
	var fsyncCalls atomic.Int64
	orig := restoreSyncFile
	restoreSyncFile = func(f *os.File) error {
		if fsyncCalls.Add(1) == 1 {
			close(enteredA)
			<-releaseA
		}
		return f.Sync()
	}
	t.Cleanup(func() { restoreSyncFile = orig })

	run := func() (string, error) {
		cmd := &cobra.Command{Use: "restore"}
		out := &bytes.Buffer{}
		cmd.SetOut(out)
		err := runPersonalDBRestore(cmd, backup, true)
		return out.String(), err
	}

	type restoreResult struct {
		out string
		err error
	}
	doneA := make(chan restoreResult, 1)
	go func() {
		out, err := run()
		doneA <- restoreResult{out, err}
	}()
	<-enteredA // A holds the entry guard, parked at the fsync seam
	// A legitimately holds its OWN staging file right now (it was
	// created before the fsync) — the invariant for B is that it adds
	// and removes NOTHING, so the directory snapshot taken here must be
	// byte-for-byte the same after B returns.
	snapA := dirListing(t, dir)

	// B runs while A is still executing: refused immediately, without
	// waiting, without staging anything, without touching the live
	// database.
	outB, errB := run()
	if errB == nil || !strings.Contains(errB.Error(), "E_DB_RESTORE_INFLIGHT") {
		t.Fatalf("restore B: error = %v, want E_DB_RESTORE_INFLIGHT", errB)
	}
	if !strings.Contains(errB.Error(), "already running") {
		t.Errorf("restore B error must name the concurrent-entry cause (not the wedge cause), got: %v", errB)
	}
	noFalseSuccess(t, outB)
	if after := fileHash(t, live); after != before {
		t.Errorf("the refused restore must not touch the live database")
	}
	if now := dirListing(t, dir); !slices.Equal(now, snapA) {
		t.Errorf("the refused restore must not create or remove any file: before %v, after %v", snapA, now)
	}

	// Release A: normal recovery — A completes the whole restore, the
	// swap is in place, the recovery file exists, and no wedge is
	// registered (every one of A's operations completed).
	close(releaseA)
	resA := <-doneA
	if resA.err != nil {
		t.Fatalf("restore A must complete once released: %v\n%s", resA.err, resA.out)
	}
	if !strings.Contains(resA.out, "[ ok  ] restored") {
		t.Errorf("restore A must print the success line, got: %s", resA.out)
	}
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("restore A must leave the restored content in place")
	}
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Errorf("restore A must keep the recovery copy: %v", serr)
	}
	if n := restoreWedgeOutstanding.Load(); n != 0 {
		t.Errorf("a completing restore must leave no outstanding wedge (got %d)", n)
	}

	// A later restore succeeds (the guard is free again).
	outC, errC := run()
	if errC != nil {
		t.Fatalf("restore C after A finished must succeed: %v\n%s", errC, outC)
	}
	if !strings.Contains(outC, "[ ok  ] restored") {
		t.Errorf("restore C must print the success line, got: %s", outC)
	}
	if after := fileHash(t, live); after != wantHash {
		t.Errorf("restore C must leave the restored content in place")
	}
	assertNoStagingLeft(t, dir)
}

// ---------------------------------------------------------------------------
// 7/8. replacement failure and rollback failure (injected renames)
// ---------------------------------------------------------------------------

func TestRestoreReplacementFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live)

	orig := restoreRename
	restoreRename = func(from, to string) error {
		if strings.Contains(from, ".restore-staging") {
			return errors.New("injected replacement failure")
		}
		return renameFileDefault(from, to)
	}
	t.Cleanup(func() { restoreRename = orig })

	out, err := runRestore(t, live, backup)
	if err == nil || !strings.Contains(err.Error(), "the replacement failed") {
		t.Fatalf("error = %v, want a replacement failure", err)
	}
	if !strings.Contains(err.Error(), "the previous database is back in place") {
		t.Errorf("error must state the rollback landed, got: %v", err)
	}
	if after := fileHash(t, live); after != before {
		t.Errorf("live database did not survive the replacement failure byte-for-byte")
	}
	if _, serr := os.Stat(live + ".restore-old"); !os.IsNotExist(serr) {
		t.Errorf("recovery file should be rolled back, stat err = %v", serr)
	}
	assertNoStagingLeft(t, dir)
	_ = out
}

func TestRestoreRollbackFailureReportedExplicitly(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	before := fileHash(t, live) // the bytes that must still exist at .restore-old

	orig := restoreRename
	restoreRename = func(from, to string) error {
		if strings.Contains(from, ".restore-staging") {
			return errors.New("injected replacement failure")
		}
		if from == live+".restore-old" && to == live {
			return errors.New("injected rollback failure")
		}
		return renameFileDefault(from, to)
	}
	t.Cleanup(func() { restoreRename = orig })

	_, err := runRestore(t, live, backup)
	if err == nil {
		t.Fatalf("restore must fail, got nil")
	}
	if !strings.Contains(err.Error(), "E_DB_RESTORE_ROLLBACK") {
		t.Errorf("rollback failure must be reported explicitly, got: %v", err)
	}
	// The recoverable data must still exist — under the aside name.
	if _, serr := os.Stat(live + ".restore-old"); serr != nil {
		t.Fatalf("previous database missing from the recovery location: %v", serr)
	}
	if got := fileHash(t, live+".restore-old"); got != before {
		t.Errorf("recovery file content differs from the original live database")
	}
	if _, serr := os.Stat(live); !os.IsNotExist(serr) {
		t.Errorf("live path should be empty after a failed replacement + failed rollback, stat err = %v", serr)
	}
}

// ---------------------------------------------------------------------------
// 9. an existing .restore-old is archived, never discarded
// ---------------------------------------------------------------------------

func TestRestorePreservesPreviousRecoveryFile(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	backup := newPopulatedPersonalDB(t, dir, "backup.db")
	liveBefore := fileHash(t, live)

	// A leftover recovery set from an earlier restore attempt.
	old := live + ".restore-old"
	previousRecovery := []byte("PREVIOUS-RECOVERY-SET — must survive this restore")
	if werr := os.WriteFile(old, previousRecovery, 0o600); werr != nil {
		t.Fatalf("write previous recovery file: %v", werr)
	}
	if werr := os.WriteFile(old+"-wal", []byte("stale-wal"), 0o600); werr != nil {
		t.Fatalf("write previous recovery wal: %v", werr)
	}

	out, err := runRestore(t, live, backup)
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "preserved as") {
		t.Errorf("output must tell the operator where the old recovery file went:\n%s", out)
	}

	// The injected recovery set is gone from the aside names…
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("readdir: %v", rerr)
	}
	archived, archivedWal := false, false
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, filepath.Base(live)+".restore-old-") {
			b, rerr2 := os.ReadFile(filepath.Join(dir, name))
			if rerr2 != nil {
				t.Fatalf("read archive %s: %v", name, rerr2)
			}
			switch {
			case strings.HasSuffix(name, "-wal"):
				archivedWal = string(b) == "stale-wal"
			default:
				archived = string(b) == string(previousRecovery)
			}
		}
	}
	if !archived {
		t.Errorf("the previous recovery file was not preserved with its content")
	}
	if !archivedWal {
		t.Errorf("the previous recovery WAL sidecar was not preserved with its content")
	}
	// …and the aside name now holds the PREVIOUS LIVE database.
	if got := fileHash(t, live+".restore-old"); got != liveBefore {
		t.Errorf(".restore-old should hold the pre-restore live database")
	}
}

// ---------------------------------------------------------------------------
// 10. backup and live database in different directories
// ---------------------------------------------------------------------------

func TestRestoreDifferentDirectories(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	live := newEmptyPersonalDB(t, dirA, "gseer.db")
	backup := newPopulatedPersonalDB(t, dirB, "backup.db")

	out, err := runRestore(t, live, backup)
	if err != nil {
		t.Fatalf("restore across directories: %v\n%s", err, out)
	}
	if got := fixtureSearchHits(t, live); got != 1 {
		t.Errorf("search after cross-directory restore hits = %d, want 1", got)
	}
	assertNoStagingLeft(t, dirA, dirB) // staging belongs next to the LIVE db, never next to the backup
}

// ---------------------------------------------------------------------------
// 11. first-run edge: the live file does not exist yet
// ---------------------------------------------------------------------------

func TestRestoreWhenLiveDatabaseMissing(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "gseer.db") // never created
	backup := newPopulatedPersonalDB(t, dir, "backup.db")

	out, err := runRestore(t, live, backup)
	if err != nil {
		t.Fatalf("restore onto a missing live path: %v\n%s", err, out)
	}
	if strings.Contains(out, "previous database is kept at") {
		t.Errorf("there is no previous database — the output must not claim one:\n%s", out)
	}
	if got := fixtureSearchHits(t, live); got != 1 {
		t.Errorf("search after restore hits = %d, want 1", got)
	}
	assertNoStagingLeft(t, dir)
}

// ---------------------------------------------------------------------------
// 12. backup equal to the live path is refused
// ---------------------------------------------------------------------------

func TestRestoreRefusesSelfRestore(t *testing.T) {
	dir := t.TempDir()
	live := newEmptyPersonalDB(t, dir, "gseer.db")
	before := fileHash(t, live)

	_, err := runRestore(t, live, live)
	if err == nil || !strings.Contains(err.Error(), "the backup path is the live database itself") {
		t.Fatalf("error = %v, want a self-restore refusal", err)
	}
	if after := fileHash(t, live); after != before {
		t.Errorf("live database changed on a refused self-restore")
	}
}
