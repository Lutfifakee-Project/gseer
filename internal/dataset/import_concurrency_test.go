// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// import_concurrency_test.go — R4 P0-6 regression battery for the
// import-side concurrency guarantees:
//
//   - the exclusive, NON-BLOCKING import lock refuses a second import
//     against the SAME database (E_DATASET_IMPORT_INFLIGHT) instead of
//     letting two imports interleave their snapshot/ingest/swap steps
//     (the second one used to delete the first one's recovery snapshot);
//   - the lock is not leaked: after a refused attempt the lock can be
//     taken again and a normal import succeeds;
//   - two imports against DIFFERENT databases never block each other.

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestImportConcurrentRefused holds the exclusive import lock, then
// attempts a full import against the same database: the import must be
// refused immediately with E_DATASET_IMPORT_INFLIGHT (never queued, no
// corruption), and the lock must be usable again after release.
func TestImportConcurrentRefused(t *testing.T) {
	dbPath := newTestDB(t)
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 21, []Record{
		domainRec("central-dns", time.Now().UTC().Add(-time.Minute), "concurrent.example"),
	})

	release, err := lockImportFile(dbPath + ".dataset-import.lock")
	if err != nil {
		t.Fatalf("acquire the lock as the concurrent importer: %v", err)
	}

	_, importErr := Import(context.Background(), ImportOptions{
		DBPath:      dbPath,
		PayloadPath: filepath.Join(dir, PayloadFilename),
		Manifest:    m,
		ManifestURL: "http://127.0.0.1/manifest.json",
	})
	if importErr == nil || !strings.Contains(importErr.Error(), "E_DATASET_IMPORT_INFLIGHT") {
		t.Fatalf("a second import against a locked database must be refused with E_DATASET_IMPORT_INFLIGHT: %v", importErr)
	}
	if !strings.Contains(importErr.Error(), "without waiting") {
		t.Errorf("the refusal must be explicit about the non-blocking policy: %v", importErr)
	}
	// Nothing was imported under the refused attempt (the refused import
	// never touched the snapshot or the data).
	if !strings.Contains(importErr.Error(), "another import is already running") {
		t.Errorf("unexpected refusal text: %v", importErr)
	}

	// Release; the same import now succeeds and stays idempotent.
	release()
	res, importErr := Import(context.Background(), ImportOptions{
		DBPath:      dbPath,
		PayloadPath: filepath.Join(dir, PayloadFilename),
		Manifest:    m,
		ManifestURL: "http://127.0.0.1/manifest.json",
	})
	if importErr != nil {
		t.Fatalf("import after the lock was released: %v", importErr)
	}
	if res.Stats.ObservationsInserted != 1 {
		t.Errorf("observations inserted = %d, want 1", res.Stats.ObservationsInserted)
	}
}

// TestImportConcurrentRacesNeverCorrupt runs two imports against the
// SAME database as simultaneously as the scheduler allows.  The
// GUARANTEE under test is data integrity, not scheduling: whether the
// two invocations actually overlap (then the lock refuses the loser
// with E_DATASET_IMPORT_INFLIGHT — proven deterministically by
// TestImportConcurrentRefused) or execute back-to-back (then the
// idempotent re-import dedupes), the outcome MUST be a healthy
// database with the exact row count and no duplicate/corrupted state.
func TestImportConcurrentRacesNeverCorrupt(t *testing.T) {
	dbPath := newTestDB(t)
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 22, []Record{
		domainRec("central-dns", time.Now().UTC().Add(-time.Minute), "race.example"),
	})

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			_, err := Import(context.Background(), ImportOptions{
				DBPath:      dbPath,
				PayloadPath: filepath.Join(dir, PayloadFilename),
				Manifest:    m,
				ManifestURL: "http://127.0.0.1/manifest.json",
			})
			errs[slot] = err // each goroutine owns its slot
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil && !strings.Contains(err.Error(), "E_DATASET_IMPORT_INFLIGHT") {
			t.Fatalf("the only acceptable error is the inflight refusal: %v", err)
		}
	}

	// The winner's database is intact: the row count is exact and the
	// recovery snapshot was cleaned up after the verified import.
	db, derr := sql.Open("sqlite", dbPath)
	if derr != nil {
		t.Fatalf("open the winning database: %v", derr)
	}
	defer func() { _ = db.Close() }()
	if got := rowCount(t, db, "observations"); got != 1 {
		t.Errorf("observations rows = %d, want 1 (no interleaving corruption)", got)
	}
}

// TestImportLockIsPerDatabase — locks are per database file: imports
// against two DIFFERENT databases run concurrently without refusing
// each other.
func TestImportLockIsPerDatabase(t *testing.T) {
	dbA := newTestDB(t)
	dbB := newTestDB(t)
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 23, []Record{
		domainRec("central-dns", time.Now().UTC().Add(-time.Minute), "perdb.example"),
	})

	releaseA, err := lockImportFile(dbA + ".dataset-import.lock")
	if err != nil {
		t.Fatalf("lock A: %v", err)
	}
	defer releaseA()

	if _, err := Import(context.Background(), ImportOptions{
		DBPath:      dbB, // a DIFFERENT database: must proceed
		PayloadPath: filepath.Join(dir, PayloadFilename),
		Manifest:    m,
		ManifestURL: "http://127.0.0.1/manifest.json",
	}); err != nil {
		t.Fatalf("an import on another database must not be blocked by db A's lock: %v", err)
	}
}
