// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build windows

package dataset

// import_lock_windows.go — Windows counterpart of the R4 P0-6 import
// lock.  LockFileEx with LOCKFILE_FAIL_IMMEDIATELY (fail immediately,
// never wait) gives the same exclusive, non-blocking semantics as the
// POSIX flock.

import (
	"fmt"
	"os"
	"syscall"
)

// lockImportFile acquires an exclusive, non-blocking byte-range lock on
// path (creating it 0600 if needed).  The returned release func unlocks
// the file; the 0-byte lock FILE itself stays as a marker.
func lockImportFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot open the import lock file: %w", err)
	}
	var ol syscall.Overlapped
	if err := syscall.LockFileEx(syscall.Handle(f.Fd()),
		syscall.LOCKFILE_EXCLUSIVE_LOCK|syscall.LOCKFILE_FAIL_IMMEDIATELY, 0,
		1, 0, &ol); err != nil {
		_ = f.Close()
		return nil, errImportInFlight
	}
	return func() {
		syscall.UnlockFileEx(syscall.Handle(f.Fd()), 0, 1, 0, &ol)
		_ = f.Close()
	}, nil
}
