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

package bench

// isolation_test.go — R5 leakage proof: two fully provisioned personal
// stores (two GSEER_HOMEs = two database files) share NOTHING.  Data
// imported into store A must be invisible to store B: zero assets, zero
// search rows, no dataset install state, no history.  (Scope-level
// isolation is pinned separately by internal/cli/scan_scope_test.go.)

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
)

// sqlOpenRO opens an existing bench database read-only intent (the file
// already exists; a plain sql.Open is safe here).
func sqlOpenRO(path string) (*sql.DB, error) { return sql.Open("sqlite", path) }

func osRemoveFile(path string) error { return os.Remove(path) }

func TestNoDataLeakBetweenIsolatedStores(t *testing.T) {
	ctx := context.Background()
	dir := benchTestDir(t)
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	// Store A: provision + import a synthetic corpus through the real
	// dataset import path.
	storeA := filepath.Join(dir, "store-a", "gseer.db")
	if err := provisionBenchDB(ctx, storeA); err != nil {
		t.Fatal(err)
	}
	payloadPath, manifest, err := buildScalePayload(filepath.Join(dir, "store-a"), 60, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = osRemoveOK(payloadPath) }()
	if _, err := dataset.Import(ctx, dataset.ImportOptions{
		DBPath:      storeA,
		PayloadPath: payloadPath,
		Manifest:    manifest,
		ManifestURL: "file://isolation-test",
	}); err != nil {
		t.Fatalf("import into store A: %v", err)
	}

	// Store B: provision ONLY — no import ever touches it.
	storeB := filepath.Join(dir, "store-b", "gseer.db")
	if err := provisionBenchDB(ctx, storeB); err != nil {
		t.Fatal(err)
	}

	dbA, err := sqlOpenRO(storeA)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dbA.Close() }()
	dbB, err := sqlOpenRO(storeB)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dbB.Close() }()

	// Sanity: store A actually holds the corpus.
	svcA := searchlite.New(dbA)
	resA, err := svcA.Search(ctx, search.Query{GQL: `port==443`, Mode: "service", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resA.Rows) == 0 {
		t.Fatal("store A must contain the imported corpus")
	}

	// The leak checks: store B sees nothing of store A's data.
	svcB := searchlite.New(dbB)
	resB, err := svcB.Search(ctx, search.Query{GQL: `port==443`, Mode: "service", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resB.Rows) != 0 {
		t.Fatalf("LEAK: store B returned %d rows for store A's data", len(resB.Rows))
	}
	var assetsB int64
	if err := dbB.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&assetsB); err != nil {
		t.Fatal(err)
	}
	if assetsB != 0 {
		t.Fatalf("LEAK: store B holds %d asset rows", assetsB)
	}

	// Install state + history are per-store too.
	stateB, err := dataset.LoadState(ctx, dbB)
	if err != nil {
		t.Fatal(err)
	}
	if stateB.Installed {
		t.Fatal("LEAK: store B reports a dataset install it never performed")
	}
	histB, err := dataset.LoadHistory(ctx, dbB, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(histB) != 0 {
		t.Fatalf("LEAK: store B holds %d history entries", len(histB))
	}
	stateA, err := dataset.LoadState(ctx, dbA)
	if err != nil {
		t.Fatal(err)
	}
	if !stateA.Installed || stateA.DatasetVersion != 1 {
		t.Fatalf("store A install state = %+v", stateA)
	}
}

func osRemoveOK(path string) error { return osRemoveFile(path) }
