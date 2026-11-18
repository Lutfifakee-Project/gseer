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

package collect

// ctlog_runner_test.go — runner-level regression for the Rev14 blocker:
// the seed-free `ctlog` connector must EXECUTE end-to-end through
// Runner.Run against the real sqlite store — registration → run →
// ingested facts → checkpoint resume — with NO seeds configured
// anywhere in the source.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCTLogRunnerSeedFreeEndToEnd(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	ctx := context.Background()

	// 30 log entries (29 x509 + 1 precert); the fixture is a static tree.
	leaves := make([][]byte, 30)
	for i := range leaves {
		leaves[i] = ctlogTestLeaf(t, ctlogEntryX509, []string{fmt.Sprintf("runner%d.example.net", i)})
	}
	leaves[29] = ctlogTestLeaf(t, ctlogEntryPrecert, []string{"runner-precert.example.net"})
	endpoint, _ := ctlogTestLog(t, 30, leaves)

	if _, err := store.EnsureSource(ctx, "central-ctlog", "ctlog", "docs/SOURCES.md §G", map[string]any{
		"seed_mode":           "none",
		"endpoint":            endpoint,
		"requests_per_second": 1000,
	}); err != nil {
		t.Fatalf("ensure source: %v", err)
	}
	if err := store.SetSourceEnabled(ctx, "central-ctlog", true); err != nil {
		t.Fatalf("enable source: %v", err)
	}

	// The registered source carries NO seeds — that is the whole point.
	src, err := store.GetSource(ctx, "central-ctlog")
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if strings.Contains(strings.ToLower(string(src.ConfigJSON)), "\"seeds\"") {
		t.Fatalf("seed-free source must not carry a seeds list: %s", src.ConfigJSON)
	}

	runner := NewRunner(store, NewClient(ClientConfig{RequestsPerSecond: 10_000, Timeout: 2 * time.Second}))

	// Run #1: discovers names from the whole static tree.
	stats, err := runner.Run(ctx, "central-ctlog")
	if err != nil {
		t.Fatalf("run #1: %v", err)
	}
	if stats.Records <= 0 || stats.Ingested <= 0 {
		t.Fatalf("seed-free run #1 must ingest facts (got %+v)", stats)
	}
	if stats.Source != "central-ctlog" || stats.Connector != "ctlog" {
		t.Fatalf("run #1 stats identity wrong: %+v", stats)
	}
	if stats.Cursor == "" {
		t.Fatalf("run #1 must checkpoint its cursor (got %+v)", stats)
	}

	// Run #2: the tree is static, so the tip-following resume at
	// cursor+1 reads NOTHING new — and must not re-ingest the old
	// window (L1 dedupe + honest zero-work).
	stats2, err := runner.Run(ctx, "central-ctlog")
	if err != nil {
		t.Fatalf("run #2: %v", err)
	}
	if stats2.Ingested != 0 {
		t.Fatalf("run #2 over a static tree must ingest nothing (got %+v)", stats2)
	}
	if stats2.Cursor != stats.Cursor {
		t.Fatalf("run #2 must leave the checkpoint intact (%q vs %q)", stats2.Cursor, stats.Cursor)
	}
}

// TestCTLogRunnerRefusesSeedModeConfig — the connector's seed-free
// contract is enforced at runner level too: a config-mode registration
// is a hard, honest fatal, never a silent seed-driven run.
func TestCTLogRunnerRefusesSeedModeConfig(t *testing.T) {
	store := newSQLiteStoreForTest(t)
	ctx := context.Background()
	endpoint, _ := ctlogTestLog(t, 1, [][]byte{ctlogTestLeaf(t, ctlogEntryX509, []string{"a.example.net"})})
	if _, err := store.EnsureSource(ctx, "bad-ctlog", "ctlog", "docs/SOURCES.md §G", map[string]any{
		"seed_mode": "config",
		"seeds":     []string{"a.example.net"},
		"endpoint":  endpoint,
	}); err != nil {
		t.Fatalf("ensure source: %v", err)
	}
	if err := store.SetSourceEnabled(ctx, "bad-ctlog", true); err != nil {
		t.Fatalf("enable source: %v", err)
	}
	runner := NewRunner(store, NewClient(ClientConfig{RequestsPerSecond: 10_000, Timeout: 2 * time.Second}))
	if _, err := runner.Run(ctx, "bad-ctlog"); err == nil || !strings.Contains(err.Error(), "seed-free") {
		t.Fatalf("seed_mode=config must be refused with the seed-free fatal (got %v)", err)
	}
}
