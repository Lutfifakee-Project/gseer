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

package postgres

import "testing"

// wantHead is the pinned migration head.  A new migration file is a
// conscious schema change: bump this constant in the same commit (the
// M13 suppression migration took the head from 4 to 5; the v0.2.0
// mandatory set — pinned 0016 + GAP-1's 0017 — takes it from 6 to 17,
// with 0007–0015 permanently reserved per OD-4).  v0.3.2 adds
// 0018_active_observation (the active-observation authorization
// surface); the v0.3.2 security microfix adds 0019_scan_concurrency_
// leases; the FINAL security microfix adds 0020_scan_lease_tokens
// (per-acquisition lease ownership tokens + renewal support).  The
// reserved band stays untouched.
const wantHead = 30

// wantFileCount is the number of embedded up-migration FILES — not the
// head version.  Versions 0007–0015 are permanently reserved (OD-4),
// so the applied-counter reports files (12) while the ledger version
// and head stay 21.
const wantFileCount = 13

// TestHeadVersion — the embedded migration set's head version is
// parsed from the highest NNNN prefix (unit; no database).
func TestHeadVersion(t *testing.T) {
	head, err := HeadVersion()
	if err != nil {
		t.Fatalf("HeadVersion error: %v", err)
	}
	if head != wantHead {
		t.Errorf("HeadVersion = %d, want %d (0001–0006 shipped v0.1.0; 0016 pinned; 0017 safe-casts; 0018 active observation; 0019 concurrency leases; 0020 lease tokens; 0021 cert projection; 0022 evidence quality; 0023 search fields; 0024 cert valid-from; 0025 ct search fields; 0026 dns search fields; 0027 perf latest tables; 0028 perf latest assets; 0029 stats indexes; 0030 hostname prefix index (R113); 0007–0015 reserved)", head, wantHead)
	}
}

func TestMigrationFiles(t *testing.T) {
	names, err := MigrationFiles()
	if err != nil {
		t.Fatalf("MigrationFiles error: %v", err)
	}
	if len(names) != 21 {
		t.Fatalf("got %d migration files, want 21 (0001–0006 + 0016–0030; the reserved 0007–0015 must never exist): %v", len(names), names)
	}
	want := []string{"0001_core.up.sql", "0002_helper_views.up.sql", "0003_search_index.up.sql", "0004_search_indexes.up.sql", "0005_suppressions.up.sql", "0006_collection.up.sql", "0016_suppression_policy_hardening.up.sql", "0017_search_safe_casts.up.sql", "0018_active_observation.up.sql", "0019_scan_concurrency_leases.up.sql", "0020_scan_lease_tokens.up.sql", "0021_cert_projection.up.sql", "0022_evidence_quality.up.sql", "0023_search_fields.up.sql", "0024_cert_valid_from.up.sql", "0025_ct_searchable.up.sql", "0026_dns_searchable.up.sql", "0027_perf_latest_tables.up.sql", "0028_perf_latest_assets.up.sql", "0029_stats_indexes.up.sql", "0030_hostname_prefix.up.sql"}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("names[%d] = %s, want %s", i, names[i], w)
		}
	}
}

func TestFileVersion(t *testing.T) {
	cases := map[string]uint{
		"0001_core.up.sql":           1,
		"0002_helper_views.up.sql":   2,
		"0004_search_indexes.up.sql": 4,
		"0012_something.up.sql":      12,
		"garbage.sql":                0,
	}
	for name, want := range cases {
		if got := fileVersion(name); got != want {
			t.Errorf("fileVersion(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestPendingFiles(t *testing.T) {
	got := pendingFiles(1, 4)
	if len(got) != 3 || got[0] != "0002_helper_views.up.sql" ||
		got[1] != "0003_search_index.up.sql" || got[2] != "0004_search_indexes.up.sql" {
		t.Errorf("pendingFiles(1,4) = %v", got)
	}
	if all := pendingFiles(0, 4); len(all) != 4 {
		t.Errorf("pendingFiles(0,4) = %v, want all four files", all)
	}
	if behind := pendingFiles(4, 4); len(behind) != 0 {
		t.Errorf("pendingFiles(4,4) = %v, want empty", behind)
	}
}
