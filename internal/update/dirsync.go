// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build !windows

package update

import "os"

// renameFileDefault is the POSIX replacement primitive: plain
// os.Rename (rename(2) — same-directory, atomic, refuses cross-device
// instead of copying).  It passes no durability flags of its own; crash
// durability is provided afterwards by syncDirDefault's directory
// fsync, which is why a failed directory sync must surface as the
// E_UPDATE_DIRSYNC warning rather than being swallowed.
func renameFileDefault(from, to string) error {
	return os.Rename(from, to)
}

// syncDirDefault flushes a directory entry to stable storage so a
// just-completed rename survives a crash: open the directory read-only,
// fsync it, and close it.  Every step's error is surfaced explicitly —
// a silent failure here would falsely claim crash durability.
func syncDirDefault(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir is the target binary's own directory, opened read-only for the rename durability sync
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
