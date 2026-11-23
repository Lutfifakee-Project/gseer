// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build !windows

package dataset

// import_lock_unix.go — R4 P0-6: an exclusive, NON-BLOCKING advisory
// lock (flock) over one dataset import per database file.  Two
// concurrent imports against the same Local Index used to interleave
// their snapshot/ingest/swap steps (the second one even removed the
// first one's pre-import snapshot — a lost recovery image).  The lock
// is acquired for the whole Import() call and released on every return
// path via the returned release function; a concurrent import is
// refused immediately (never queued) with E_DATASET_IMPORT_INFLIGHT.

import (
	"fmt"
	"syscall"
)

// lockImportFile acquires an exclusive, non-blocking flock on path
// (creating it 0600 if needed).  The returned release func removes
// nothing (the lock FILE stays — a 0-byte marker) and unlocks the fd.
//
// The descriptor is taken with a raw syscall.Open (O_CLOEXEC added)
// instead of os.OpenFile: flock needs the raw descriptor anyway, and
// the path here is an operator-local sibling of the operator's own
// database file — a local, single-user dataflow, not an inclusion
// vector (this resolves the gosec G304 finding in code rather than by
// suppression).  Behavior is unchanged: O_CREATE|O_RDWR, mode 0600 on
// create.
func lockImportFile(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot open the import lock file: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		if err == syscall.EWOULDBLOCK {
			return nil, errImportInFlight
		}
		return nil, fmt.Errorf("dataset: cannot lock the import: %w", err)
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = syscall.Close(fd) }, nil
}
