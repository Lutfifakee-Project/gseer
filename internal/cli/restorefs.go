// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build !windows

package cli

import "os"

// renameFileDefault is the POSIX replacement primitive: plain
// os.Rename (rename(2) — same-directory, atomic per call, refuses
// cross-device instead of copying; the staged restore file always
// lives in the live database's own directory, so both renames of the
// swap are same-directory).  It passes no durability flags of its
// own; crash durability is provided afterwards by syncDirDefault's
// directory fsync — which is why a failed directory sync surfaces as
// an explicit E_DB_RESTORE_DIRSYNC error instead of being swallowed.
func renameFileDefault(from, to string) error {
	return os.Rename(from, to)
}

// syncDirDefault flushes a directory entry to stable storage so a
// just-completed rename survives a crash: open the directory
// read-only, fsync it, and close it.  Every step's error is surfaced
// explicitly — a silent failure here would falsely claim crash
// durability for the replacement.
func syncDirDefault(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the live database's own directory, opened read-only for the rename durability sync
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	// The sync result is the primary operation; the close error only
	// matters when the sync succeeded.
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
