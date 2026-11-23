// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build !windows

package dataset

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression coverage for the R12 remediation of lockImportFile
// (syscall.Open instead of os.OpenFile): identical observable behavior —
// the lock file is created 0600, a concurrent acquisition is refused
// with errImportInFlight, and release restores availability.
func TestLockImportFileBehaviorUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "import.lock")
	release, err := lockImportFile(path)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock file: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("lock file mode = %v, want 0600", got)
	}
	_, err = lockImportFile(path)
	if err == nil {
		t.Fatal("second concurrent lock must be refused")
	}
	if err != errImportInFlight {
		t.Fatalf("second lock error = %v, want errImportInFlight", err)
	}
	release()
	release2, err := lockImportFile(path)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	release2()
}
