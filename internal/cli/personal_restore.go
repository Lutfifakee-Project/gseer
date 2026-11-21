// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// personal_restore.go — the personal-mode `gseer db restore` backend.
//
// Guarantee model (honest terms): this is a RECOVERABLE REPLACEMENT,
// never claimed as "atomic".  The sequence:
//
//  1. the backup is probed (real SQLite open) and then fully STAGED
//     in a fresh temporary file inside the live database's own
//     directory — same volume, so the final rename stays a rename —
//     written with O_EXCL (a staging path can never clobber anything),
//     fsynced, closed with its error checked, chmod'ed 0600 after the
//     umask, and validated with a real SQLite open + PRAGMA
//     quick_check;
//  2. only after the staged copy is proven good, the live database
//     AND its -wal/-shm sidecars are moved aside to
//     <db>.restore-old* — the sidecars move WITH the database so a
//     stale WAL can never be crash-recovered against the new file
//     (moving the main file while leaving the WAL in place would be
//     exactly that corruption window);
//  3. the staged file is renamed onto the live path — same-directory
//     rename, atomic per step on POSIX, MoveFileExW with
//     REPLACE_EXISTING|WRITE_THROUGH on Windows (see
//     restorefs_windows.go);
//  4. any failure before or during the swap rolls the recorded
//     renames back in reverse order, and a FAILED ROLLBACK is
//     reported explicitly with the exact location of every artifact —
//     never silently ignored.
//
// Between the live file's rename aside (step 2) and the staged file's
// rename in (step 3) the live path briefly does not exist.  A crash
// in that window loses nothing — the previous database is intact at
// <db>.restore-old — and that is precisely why user-facing text says
// "recoverable replacement", not "atomic".
//
// A previous <db>.restore-old is NEVER discarded: it is archived to a
// unique <db>.restore-old-<timestamp> first and the operator is told
// where it went.
//
// Open-handle lifecycle: this command process never opens the live
// database (only the backup and the staged copy).  A concurrently
// running GSEER process keeps its POSIX file handles working across
// the renames (they follow the inode); on Windows an open live file
// or sidecar makes the rename fail — which aborts the restore cleanly
// with everything rolled back.  Either way the operator is asked to
// run the restore while no other GSEER process is using the database.
//
// FIX ROUND 4 — watchdog completeness.  FIX ROUND 3 bounded the three
// durability waits (staged fsync, staging SQLite close, directory
// fsync).  The audit found the remaining unbounded waits and lifecycle
// gaps; FIX ROUND 4 closes them:
//
//  1. EVERY sql.DB close on every path is bounded (backup probe close,
//     staged-copy close on the success path AND on the integrity-failure
//     path).  The probe close is trivial today (sqlite.Open is lazy — an
//     existing file opens no connection), but the bound is mechanical:
//     the invariant cannot silently regress if the opener ever starts
//     pinging.
//  2. The staged-copy FILE close is bounded too: close(2) on a file
//     whose fsync is still in flight can itself block (NFS close waits
//     for the outstanding writeback — exactly what a timed-out fsync
//     leaves behind), so a bounded fsync must never be followed by an
//     unbounded close.  On a timed-out fsync/close the cleanup SKIPS
//     the second real out.Close(): os.File.Close serializes on an
//     internal mutex, so it would wait behind the wedged one and hang
//     the cleanup — the staging path is unlinked instead, which is
//     safe while the fd is held.
//  3. Lifecycle when a watchdog expires: the leaked goroutine keeps
//     the fds of the (already unlinked) staging inode; an fsync writes
//     no content, a deferred SQLite close checkpoint-writes only to
//     the unlinked inode and unlinks sidecars BY NAME — which is why a
//     new restore in the same process FAILS CLOSED (see
//     restoreWedgeOutstanding) until the outstanding operation drains.
//     The CLI is one-shot per process, so in production the wedge and
//     its fds die with the process; the registry makes the in-process
//     retry policy explicit and testable instead of implicit.
//  4. Scoped honestly: metadata operations (stat/lstat/chmod/remove/
//     rename, directory listing) can also block on pathological
//     storage, but they are not durability waits — they are required
//     for the swap itself and are left plain; the wedge class fixed
//     here is the one the owner evidence showed (durability syncs and
//     the driver's close-time checkpoint).
//
// FIX ROUND 5 — restore entry concurrency guard.  FIX ROUND 4 made the
// outstanding-wedge policy fail-closed, but two restores RUNNING AT
// THE SAME TIME in one process could still interleave: the second
// restore would pass the wedge registry (nothing outstanding yet),
// stage its own copy, and then race the first restore's swap against
// the SAME live path — its .restore-old step would archive the first
// restore's freshly installed database, and the two directory fsyncs
// would race.  FIX ROUND 5 adds an exclusive, NON-BLOCKING entry
// guard (restoreEntryGuard): exactly one runPersonalDBRestore executes
// at a time; a concurrent invocation is refused immediately with the
// stable code E_DB_RESTORE_INFLIGHT instead of waiting.  The guard is
// acquired BEFORE the outstanding-wedge check (only one invocation at
// a time reaches the registry) and released on every normal return
// and error path via defer; a timed-out underlying operation remains
// protected by restoreWedgeOutstanding after the function returns —
// the janitor decrements only when the operation itself completes.

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// Test seams: production always uses the real syscalls and the real
// sqlite opener; the regression tests swap these package-level
// variables to inject deterministic copy/sync/close/rename/sync-dir
// failures without fake filesystems, FUSE mounts, or unreliable
// permission tricks (which behave differently under root).  Mirrors
// the seam pattern of internal/update/apply.go.
var (
	restoreOpenSrc    = func(name string) (io.ReadCloser, error) { return os.Open(name) } //nolint:gosec // G304: the operator-supplied backup path IS the feature
	restoreSyncFile   = func(f *os.File) error { return f.Sync() }
	restoreCloseFile  = func(f *os.File) error { return f.Close() }
	restoreCloseDB    = func(db *sql.DB) error { return db.Close() }
	restoreRename     = renameFileDefault
	restoreSyncDir    = syncDirDefault
	restoreSQLiteOpen = sqlite.Open

	// restoreSyncTimeout bounds how long the CLI WAITS on a sync
	// primitive (staged-copy fsync AND close, the SQLite driver's
	// close-time checkpoint+fsync on every path, the directory fsync).
	// FIX ROUND 3: on storage whose journal commit wedges (full
	// journal, NFS server gone, failing disk) an fsync never returns
	// and the old code hung the CLI forever — threads parked in
	// futex/wait_woken with no output and no error.  fsync cannot be
	// cancelled from userspace, so the watchdog does NOT skip or abort
	// the sync: it stops WAITING and reports explicitly.  Durability
	// terms stay the honest ones this file already uses: on expiry the
	// operation's durability is UNCONFIRMED, never silently assumed.
	// Tests shrink this value.
	restoreSyncTimeout = 30 * time.Second
)

// restoreWedgeOutstanding counts sync operations that have already
// outlived their bounded wait in THIS process and are still running in
// their leaked watchdog goroutines.  FIX ROUND 4 fail-closed policy:
// while it is non-zero, a NEW restore in the same process is refused —
// a wedged SQLite close still holds the staged database open, and when
// storage recovers it performs its deferred checkpoint and its by-name
// -wal/-shm cleanup; letting a new restore reuse the staging path
// first could collide with those deferred operations (the staging
// inode is unlinked, but the NAMES would be reused).  The CLI is
// one-shot per process, so in production the wedge dies with the
// process and the kernel drops its fds — the registry is what makes
// the in-process retry policy explicit and testable instead of
// implicit.  Each outstanding operation decrements the counter exactly
// once, when its operation finally completes (restoreBoundedSync's
// janitor), so the policy self-heals when storage recovers.
var restoreWedgeOutstanding atomic.Int64

// restoreEntryGuard serializes restore invocations within one process:
// only ONE runPersonalDBRestore may execute at a time.  FIX ROUND 5:
// two concurrent restores would interleave their staging and swap
// steps against the same live database path — the staging PATH is
// unique per attempt, but the swap targets the same live file, so the
// second restore's .restore-old step would archive the first restore's
// freshly installed database and the two directory fsyncs would race.
// The guard is EXCLUSIVE and NON-BLOCKING (sync.Mutex.TryLock): a
// concurrent invocation fails immediately with the stable code
// E_DB_RESTORE_INFLIGHT, never queues.  It is acquired at the very top
// of runPersonalDBRestore — before the outstanding-wedge registry
// check — and released on every normal return and error path via
// defer.  A timed-out underlying operation stays protected by
// restoreWedgeOutstanding AFTER the guard is released (the janitor
// decrements only when the operation itself completes), so the two
// layers compose: the guard excludes simultaneous execution, the
// registry excludes retries while an earlier operation is still
// outstanding.
var restoreEntryGuard sync.Mutex

// errRestoreSyncStuck marks every bounded-sync expiry (errors.Is target).
var errRestoreSyncStuck = errors.New("bounded sync wait expired (storage wedged)")

// restoreBoundedSync runs run() and waits at most restoreSyncTimeout for
// it.  On expiry it returns an explicit E_DB_RESTORE_SYNC_STUCK error
// naming the stuck operation; the goroutine keeps running (a wedged
// fsync cannot be cancelled — the buffered channel means it never
// blocks anyone else, it just finishes or wedges on its own), and the
// caller's cleanup (removing a not-yet-installed staging file) is safe
// on POSIX even while the sync is still in flight (unlink is
// independent of the fd).
//
// FIX ROUND 4: an expiry also registers the operation in
// restoreWedgeOutstanding (fail-closed input — see the var comment).
// The pairing is race-free by construction: the increment happens only
// when the completion channel is still empty at expiry (re-checked
// non-blockingly, so an operation completing "just in time" is never
// miscounted), and a per-invocation janitor decrements exactly once
// when the operation eventually completes — no flag the leaked
// goroutine and the watchdog could observe in different orders.  If
// the operation never completes (true wedge until process exit), the
// registration stays and every further restore in this process fails
// closed.
func restoreBoundedSync(op string, run func() error) error {
	return restoreBoundedSyncAfter(op, run, nil)
}

// restoreBoundedSyncAfter is restoreBoundedSync with an after hook.  The
// hook runs ON THE JANITOR GOROUTINE, after the wedged operation
// eventually completes (or never — then the janitor simply never runs)
// and BEFORE the outstanding-wedge count is decremented, so anything
// that drains the wedge registry observes the hook's effects.  On the
// healthy path the hook never runs: the caller's normal flow owns the
// cleanup.
//
// The hook exists for Windows cleanup semantics.  On POSIX the immediate
// wedge cleanup unlinks files whose handles the still-in-flight
// operation holds (unlink-while-open); on Windows the same removal fails
// with a sharing violation until the handle is released.  Retrying the
// removal once the operation completes closes that gap without touching
// the fail-closed contract or the explicit leftover note (which stays
// accurate for a wedge that never resolves).
func restoreBoundedSyncAfter(op string, run func() error, after func()) error {
	type syncResult struct{ err error }
	ch := make(chan syncResult, 1)
	done := make(chan struct{})
	go func() {
		ch <- syncResult{run()}
		close(done)
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(restoreSyncTimeout):
		// The operation may have completed while the timer fired:
		// re-check the channel non-blockingly first, so a completing
		// operation is never registered as outstanding.
		select {
		case r := <-ch:
			return r.err
		default:
		}
		restoreWedgeOutstanding.Add(1)
		go func() {
			<-done // the wedged operation completed (or never will — then this janitor simply never runs)
			if after != nil {
				after()
			}
			restoreWedgeOutstanding.Add(-1)
		}()
		return fmt.Errorf("E_DB_RESTORE_SYNC_STUCK: %w: the %s did not return within %s — the storage layer appears wedged (full journal, NFS server gone, failing disk). The sync itself cannot be cancelled and continues in the background; DURABILITY IS UNCONFIRMED for this operation. Verify with `gseer search` / `gseer doctor` and re-run the restore when storage is healthy", errRestoreSyncStuck, op, restoreSyncTimeout)
	}
}

// removeStagingArtifacts unlinks the staging file and its SQLite
// sidecars.  POSIX unlink is safe while a leaked watchdog goroutine
// still holds the fds; SQLite cannot resurrect a deleted WAL by name
// during the eventual real close (close only ever DELETES its own
// sidecar names).  Returns the paths that could NOT be removed —
// reported by the caller, never silently discarded.
func removeStagingArtifacts(staging string) []string {
	var leftover []string
	if rerr := os.Remove(staging); rerr != nil && !os.IsNotExist(rerr) {
		leftover = append(leftover, staging)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if rerr := os.Remove(staging + suffix); rerr != nil && !os.IsNotExist(rerr) {
			leftover = append(leftover, staging+suffix)
		}
	}
	return leftover
}

// stagingLeftoverNote renders the explicit leftover note for a cleanup
// that could not remove everything ("" when the directory is clean).
func stagingLeftoverNote(leftover []string) string {
	if len(leftover) == 0 {
		return ""
	}
	return " — leftover staging artifacts that can be deleted once no process uses them: " + strings.Join(leftover, ", ")
}

// restoreNoChmodErr reports whether a chmod error is the expected
// no-op on platforms without POSIX mode bits (mirrors the storage
// package's tolerance — the file ACL follows the parent directory
// there).
func restoreNoChmodErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, sub := range []string{"not supported", "not implemented", "ENOSYS", "EWINDOWS"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

// uniqueRestorePath returns a path that does not exist right now:
// base itself when free, otherwise base.1, base.2, …  The O_EXCL in
// copyFile and the rename below stay the real guards against races;
// this loop only picks a sensible candidate (bounded, personal-mode
// scale).
func uniqueRestorePath(base string) (string, error) {
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		return base, nil
	}
	for i := 1; i < 10000; i++ {
		cand := fmt.Sprintf("%s.%d", base, i)
		if _, err := os.Lstat(cand); os.IsNotExist(err) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("cannot find a free aside path next to %s", base)
}

// copyFile copies src to dst, creating dst exclusively with mode and
// returning only after dst is fully written, fsynced, closed AND
// chmod'ed — a nil return means the copy is really on disk with the
// requested permissions.  dst is ALWAYS opened with O_EXCL: this
// helper must never truncate or clobber an existing file (the live
// database is never a copyFile destination — the replacement happens
// exclusively through renames of a fully staged, validated copy).
// Error precedence: the first primary failure (open, copy, sync,
// chmod) wins; the close error surfaces only when nothing earlier
// failed, so cleanup never masks the operation's own error.  A failed
// copy releases the handle even when the close itself failed, and
// removes its own partial dst; a removal that still fails is REPORTED
// together with the primary error, never silently discarded.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := restoreOpenSrc(src) //nolint:gosec // G304: operator-supplied backup/restore path is the feature
	if err != nil {
		return err
	}
	// The backup source handle is closed read-only in the deferred
	// close below and is deliberately NOT bounded: a read-only fd has
	// no dirty page writeback, POSIX close does not wait for in-flight
	// reads, and NFS close-to-open consistency only concerns writes —
	// this close cannot wedge on the storage classes in scope here.
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: a fresh staging path inside the database's own directory
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	if copyErr == nil {
		// FIX ROUND 3: bounded wait — a wedged storage layer must
		// surface as an explicit error, not an infinite CLI hang.
		// The seam is captured into a local BEFORE the bounded call:
		// the watchdog goroutine must never read the package-level
		// seam var (a cleanup/test could restore it concurrently —
		// an unsynchronized access the race detector rightly flags).
		syncFile := restoreSyncFile
		copyErr = restoreBoundedSync("fsync of the staged copy", func() error {
			return syncFile(out)
		})
	}
	// FIX ROUND 4: the staged-copy file close is bounded as well.  A
	// close(2) with an fsync still in flight can itself block (NFS
	// close waits for the outstanding writeback — exactly what the
	// timed-out fsync above leaves behind), so a bounded fsync must
	// never be followed by an unbounded close.  Same seam-capture rule
	// as the fsync above.
	closeFile := restoreCloseFile
	closeErr := restoreBoundedSyncAfter("close of the staged copy", func() error {
		return closeFile(out)
	}, func() {
		// Windows: the immediate wedge cleanup below cannot remove dst
		// while this still-in-flight close holds the handle (sharing
		// violation).  Once the wedged close completes, the janitor
		// retries the removal — on POSIX the file was already unlinked
		// and IsNotExist is a no-op.
		_ = os.Remove(dst)
	})
	if copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		if errors.Is(copyErr, errRestoreSyncStuck) {
			// FIX ROUND 4: a TIMED-OUT fsync or close is still IN
			// FLIGHT inside the leaked goroutine and holds the real
			// handle.  Do NOT call out.Close() again here: os.File
			// serializes closes on an internal mutex, so a second
			// close would wait behind the wedged one and hang the
			// cleanup — the exact hang this fix removes.  Unlink the
			// staging path instead (safe on POSIX while the fd is
			// held; the in-flight operation keeps working on the
			// unlinked inode and cannot write anything back by
			// name).  A removal that still fails (Windows sharing
			// violation) is REPORTED, never silently discarded.
			if rerr := os.Remove(dst); rerr != nil {
				return fmt.Errorf("%w (cleanup: the partial staging file could not be removed and is still at %s: %v — it can be deleted once no process uses it)", copyErr, dst, rerr)
			}
			return copyErr
		}
		// A FAILED (fast) close can leave the underlying handle OPEN
		// (the seam in tests simulates it; a real EINTR/EIO close or a
		// failed CloseHandle does it in production).  Removing an
		// open file fails on Windows with a sharing violation, which
		// used to silently leave a partial staging file behind.  The
		// cleanup therefore releases the REAL handle first —
		// out.Close(), deliberately NOT the seam, whose injected
		// failure is exactly what the cleanup must survive — and
		// only then removes the partial destination.  This second
		// close is safe on this path: the failed close is no longer
		// in flight, and on an already-closed *os.File it returns
		// os.ErrClosed, an expected non-failure.  Its own error
		// carries no recoverable information beyond what the Remove
		// below surfaces: if the handle somehow survived, the Remove
		// fails on Windows and THAT error is reported next to the
		// primary one instead of being silently discarded.
		_ = out.Close()
		if rerr := os.Remove(dst); rerr != nil {
			return fmt.Errorf("%w (cleanup: the partial staging file could not be removed and is still at %s: %v — it can be deleted once no process uses it)", copyErr, dst, rerr)
		}
		return copyErr
	}
	// The umask can only clear bits on the O_CREATE mode — re-assert
	// the 0600 policy explicitly after the data is durable.
	if err := os.Chmod(dst, mode); err != nil && !restoreNoChmodErr(err) {
		_ = os.Remove(dst)
		return fmt.Errorf("cannot set %04o on the staged copy: %w", mode, err)
	}
	return nil
}

// quickCheck runs PRAGMA quick_check and requires the literal "ok".
func quickCheck(db *sql.DB) error {
	var out string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&out); err != nil {
		return err
	}
	if out != "ok" {
		return fmt.Errorf("quick_check reported %q", out)
	}
	return nil
}

// stageValidatedRestoreCopy probes the backup with a real SQLite open,
// stages a full copy of it in a fresh exclusive file next to the live
// database, and validates the STAGED copy (real SQLite open +
// quick_check + the 0600 policy) before anything is replaced.  The
// live database is not touched anywhere in this step; on failure no
// staging file is left behind.
func stageValidatedRestoreCopy(backup, live string) (string, error) {
	// FIX ROUND 4: every sql.DB close on every path below goes through
	// the same bounded wrapper with the seam captured into a local —
	// the invariant "no unbounded close on the restore path" is
	// mechanical, not incidental.
	closeDB := restoreCloseDB

	probe, err := restoreSQLiteOpen(backup)
	if err != nil {
		return "", fmt.Errorf("E_DB_RESTORE: the backup file is not a valid GSEER database: %w", err)
	}
	// The probe pool holds no connection today (sqlite.Open is lazy:
	// an existing file opens nothing), so this close is trivial — but
	// it is bounded anyway so the invariant cannot silently regress if
	// the opener ever starts pinging (FIX ROUND 4, audit item 1).
	if cerr := restoreBoundedSync("close of the backup probe", func() error {
		return closeDB(probe.DB)
	}); cerr != nil {
		return "", fmt.Errorf("E_DB_RESTORE: the backup probe could not be closed cleanly (the live database was not touched): %w", cerr)
	}

	staging, err := uniqueRestorePath(live + ".restore-staging")
	if err != nil {
		return "", fmt.Errorf("E_DB_RESTORE: %w", err)
	}
	if err := copyFile(backup, staging, 0o600); err != nil {
		return "", fmt.Errorf("E_DB_RESTORE: cannot stage the backup copy (the live database was not touched): %w", err)
	}

	validated, err := restoreSQLiteOpen(staging)
	if err != nil {
		_ = os.Remove(staging)
		return "", fmt.Errorf("E_DB_RESTORE: the staged copy is not a valid database (the live database was not touched): %w", err)
	}
	if qerr := quickCheck(validated.DB); qerr != nil {
		// FIX ROUND 4 (audit item 1): this path previously closed the
		// staging database UNBOUNDED — a real connection exists here
		// (quickCheck just ran), so its close-time checkpoint+fsync is
		// exactly the wedge class the owner hit.  Bounded on every
		// path now.
		cerr := restoreBoundedSyncAfter("close of the staged copy after a failed integrity check (checkpoint + fsync on close)", func() error {
			return closeDB(validated.DB)
		}, func() {
			// Windows retry: the immediate removal below fails with a
			// sharing violation while the wedged close still holds the
			// handles; once the real close has completed, the janitor
			// removes what is left.  POSIX: already unlinked, no-op.
			removeStagingArtifacts(staging)
		})
		leftover := removeStagingArtifacts(staging)
		if errors.Is(cerr, errRestoreSyncStuck) {
			return "", fmt.Errorf("E_DB_RESTORE: the staged copy failed the integrity check (%v), and its close did not return within %s either — the live database was not touched; the integrity error is the primary failure, the wedge only delays the cleanup: %w%s", qerr, restoreSyncTimeout, cerr, stagingLeftoverNote(leftover))
		}
		return "", fmt.Errorf("E_DB_RESTORE: the staged copy failed the integrity check (the live database was not touched): %w%s", qerr, stagingLeftoverNote(leftover))
	}
	// FIX ROUND 3: the last pool connection's close is where SQLite
	// checkpoints the WAL, fsyncs and removes the sidecars — on wedged
	// storage this wait never returned.  Bounded now (through the
	// restoreCloseDB seam, captured locally — see above — so the
	// watchdog goroutine never reads the package var); a wedge aborts
	// the restore with the staging file removed (POSIX unlink is safe
	// while the leaked goroutine still holds the fd) and the live
	// database untouched.  On Windows the immediate removal cannot run
	// while the wedged close holds the handles — the janitor retries it
	// after the real close completes (restoreBoundedSyncAfter).
	if cerr := restoreBoundedSyncAfter("close of the validated staging copy (checkpoint + fsync on close)", func() error {
		return closeDB(validated.DB)
	}, func() {
		// Windows retry after the real close: sqlite deleted its own
		// sidecars, the handles are released, so the staging set comes
		// down now.  POSIX: already unlinked — IsNotExist is a no-op.
		removeStagingArtifacts(staging)
	}); cerr != nil {
		// The staging file and its sidecars are not installed anywhere:
		// remove them (POSIX unlink is safe while the leaked goroutine
		// still holds the fds; sqlite cannot resurrect a deleted WAL by
		// name during the eventual real close) and say exactly where
		// anything that survived is, never silently.  On Windows a
		// removal that still fails is REPORTED here — and retried by
		// the janitor once the wedged close releases the handles.
		leftover := removeStagingArtifacts(staging)
		return "", fmt.Errorf("E_DB_RESTORE: the staged copy could not be closed cleanly (the live database was not touched): %w%s", cerr, stagingLeftoverNote(leftover))
	}

	// Permissive-mode refusal: the staged copy must carry the same
	// restrictive permission policy as the live database file.
	if st, serr := os.Stat(staging); serr == nil {
		if perm := st.Mode().Perm(); perm&0o177 != 0 {
			_ = os.Remove(staging)
			return "", fmt.Errorf("E_DB_RESTORE: staged copy has permissive mode %04o, refusing to install it (the live database was not touched)", uint32(perm))
		}
	}
	return staging, nil
}

// archivePreviousRecoveryFile never discards a previous <db>.restore-old:
// it renames the old recovery set (main file + sidecars) to a unique
// timestamped name and returns the operator-facing note, or an error.
func archivePreviousRecoveryFile(old string) (string, error) {
	if _, serr := os.Lstat(old); serr != nil {
		return "", nil // nothing to archive
	}
	archived, uerr := uniqueRestorePath(old + "-" + time.Now().UTC().Format("20060102T150405"))
	if uerr != nil {
		return "", fmt.Errorf("E_DB_RESTORE: cannot archive the previous recovery file: %w", uerr)
	}
	if rerr := restoreRename(old, archived); rerr != nil {
		return "", fmt.Errorf("E_DB_RESTORE: cannot set the previous recovery file aside (nothing was replaced): %w", rerr)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		side := old + suffix
		if _, serr := os.Lstat(side); serr == nil {
			_ = restoreRename(side, archived+suffix) // best effort: the main file is what matters
		}
	}
	return fmt.Sprintf("the previous recovery file was preserved as %s (never discarded)", archived), nil
}

// swapStagedRestore performs the recoverable replacement: move the
// live database AND its WAL/SHM sidecars aside, then rename the staged
// copy onto the live path.  Every completed rename is journaled for
// reverse-order rollback; a rollback that itself fails is reported
// explicitly (errors.Join) with the location of every artifact.  On a
// failed replacement the staging file is removed only when the
// rollback succeeded — after a failed rollback every recoverable
// artifact stays on disk.
func swapStagedRestore(staging, live, old string) error {
	type renameStep struct{ from, to string }
	var done []renameStep
	undo := func() error {
		var first error
		for i := len(done) - 1; i >= 0; i-- {
			if rerr := restoreRename(done[i].to, done[i].from); rerr != nil && first == nil {
				first = rerr
			}
		}
		return first
	}
	step := func(from, to string) error {
		if rerr := restoreRename(from, to); rerr != nil {
			return rerr
		}
		done = append(done, renameStep{from, to})
		return nil
	}

	liveExists := true
	if _, serr := os.Stat(live); serr != nil {
		if !os.IsNotExist(serr) {
			return fmt.Errorf("E_DB_RESTORE: cannot stat the live database: %w", serr)
		}
		liveExists = false // first-run edge: the config names a file that does not exist yet
	}

	if liveExists {
		if rerr := step(live, old); rerr != nil {
			if uerr := undo(); uerr != nil {
				return errors.Join(
					fmt.Errorf("E_DB_RESTORE: cannot move the live database aside: %w", rerr),
					fmt.Errorf("E_DB_RESTORE_ROLLBACK: the rollback ALSO failed — data is preserved, but files may be out of place; do not run GSEER until this is resolved: %w", uerr),
				)
			}
			_ = os.Remove(staging)
			return fmt.Errorf("E_DB_RESTORE: cannot move the live database aside (everything is back in place): %w", rerr)
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			side := live + suffix
			if _, serr := os.Lstat(side); serr == nil {
				if rerr := step(side, old+suffix); rerr != nil {
					if uerr := undo(); uerr != nil {
						return errors.Join(
							fmt.Errorf("E_DB_RESTORE: cannot move the database sidecar %s aside: %w", side, rerr),
							fmt.Errorf("E_DB_RESTORE_ROLLBACK: the rollback ALSO failed — do not run GSEER; the previous database is at %s, its sidecars may need a manual move back", old),
						)
					}
					_ = os.Remove(staging)
					return fmt.Errorf("E_DB_RESTORE: cannot move the database sidecar %s aside (everything is back in place): %w", side, rerr)
				}
			}
		}
	}

	if rerr := step(staging, live); rerr != nil {
		if uerr := undo(); uerr != nil {
			return errors.Join(
				fmt.Errorf("E_DB_RESTORE: the replacement failed: %w", rerr),
				fmt.Errorf("E_DB_RESTORE_ROLLBACK: the rollback ALSO failed — do not run GSEER; the previous database (with its sidecars) is preserved next to %s under the .restore-old names; move them back manually", live),
			)
		}
		_ = os.Remove(staging)
		return fmt.Errorf("E_DB_RESTORE: the replacement failed (the previous database is back in place): %w", rerr)
	}
	return nil
}

// runPersonalDBRestore replaces the live personal database with the
// backup — staged, validated, recoverable (see the file comment for
// the full guarantee model; it is deliberately NOT documented as
// atomic).
func runPersonalDBRestore(cmd *cobra.Command, backupPath string, yes bool) error {
	// FIX ROUND 5: exclusive, non-blocking entry guard — acquired
	// before the outstanding-wedge check below (only one invocation at
	// a time reaches the registry) and released on EVERY return path
	// via defer.  A concurrent invocation is refused immediately,
	// never queued: see the restoreEntryGuard comment.
	if !restoreEntryGuard.TryLock() {
		return fmt.Errorf("E_DB_RESTORE_INFLIGHT: another restore is already running in this process — refused without waiting (non-blocking): a restore stages into and replaces the live database, so two running at once could interleave their staging and swap steps; wait for the running restore to finish and re-run")
	}
	defer restoreEntryGuard.Unlock()

	cfg, err := loadEngineConfig()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(backupPath)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(abs); serr != nil {
		return fmt.Errorf("E_DB_RESTORE: backup file not found: %w", serr)
	}
	live := filepath.Clean(cfg.Database.DSN)
	if live == filepath.Clean(abs) {
		return fmt.Errorf("E_DB_RESTORE: the backup path is the live database itself — nothing to restore")
	}
	// FIX ROUND 4 fail-closed policy: refuse a new restore while a
	// previous one's sync operation is still outstanding on wedged
	// storage (its deferred SQLite checkpoint / by-name sidecar cleanup
	// could collide with a reused staging path — see the
	// restoreWedgeOutstanding comment).  The policy self-heals when the
	// outstanding operation drains; in the one-shot CLI the wedge dies
	// with the process.
	if n := restoreWedgeOutstanding.Load(); n > 0 {
		return fmt.Errorf("E_DB_RESTORE_INFLIGHT: %d previous restore sync operation(s) in this process are still outstanding on wedged storage (their deferred SQLite checkpoint and sidecar cleanup are not finished). Fail-closed: re-run the restore from a fresh process, or wait for storage to recover and retry — proceeding first could collide with the outstanding operations", n)
	}
	if !yes {
		out := cmd.OutOrStdout()
		printf(out, "This REPLACES the personal database %s with %s (the current database is kept aside).\nProceed? [y/N] ", live, abs)
		var answer string
		if _, err := fmt.Fscanln(cmd.InOrStdin(), &answer); err != nil || (answer != "y" && answer != "yes") {
			println(out, "Restore cancelled.")
			return nil
		}
	}
	out := cmd.OutOrStdout()

	staging, err := stageValidatedRestoreCopy(abs, live)
	if err != nil {
		return err
	}

	old := live + ".restore-old"
	note, err := archivePreviousRecoveryFile(old)
	if err != nil {
		_ = os.Remove(staging)
		return err
	}
	if note != "" {
		printf(out, "[note ] %s\n", note)
	}

	if err := swapStagedRestore(staging, live, old); err != nil {
		return err
	}

	// Crash durability for the swap: fsync the directory on POSIX (a
	// no-op-with-barrier on Windows — see restorefs_windows.go).  The
	// replacement has ALREADY happened here: a failure must be
	// reported, never rolled back.  FIX ROUND 3: bounded wait — on
	// wedged storage this fsync never returned and the CLI hung past
	// the successful swap with no output; now it reports explicitly
	// (same E_DB_RESTORE_DIRSYNC semantics: restore IS in place,
	// durability unconfirmed).
	syncDir := restoreSyncDir // captured locally before the goroutine (see copyFile)
	if serr := restoreBoundedSync("directory fsync after the replacement", func() error {
		return syncDir(filepath.Dir(live))
	}); serr != nil {
		if errors.Is(serr, errRestoreSyncStuck) {
			return fmt.Errorf("E_DB_RESTORE_DIRSYNC: the restore IS in place, but the %w — after a crash or power loss the previous database file may reappear. Verify with `gseer search` and re-run the restore to make it durable", serr)
		}
		return fmt.Errorf("E_DB_RESTORE_DIRSYNC: the restore IS in place, but flushing the directory entry to disk failed — after a crash or power loss the previous database file may reappear. Verify with `gseer search` and re-run the restore to make it durable: %w", serr)
	}

	// Done.  The recovery copy stays until the operator removes it.
	printf(out, "[ ok  ] restored %s from %s (recoverable replacement)\n", live, abs)
	if _, serr := os.Stat(old); serr == nil {
		printf(out, "The previous database is kept at %s (remove it when satisfied).\n", old)
		if _, werr := os.Lstat(old + "-wal"); werr == nil {
			printf(out, "Its WAL sidecar is kept at %s (kept together so the recovery set stays complete).\n", old+"-wal")
		}
		printf(out, "If anything looks wrong, recover with:\n  mv %s %s\n", old, live)
	}
	return nil
}
