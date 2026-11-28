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

// scale_test.go — small, fast proofs for the scale/quality harness:
// the synthetic corpus is valid through the REAL dataset import path,
// the labeled ground truth is consistent with the generator, and a
// scaled import reproduces honest measurements.

import (
	"context"
	"os"
	"testing"
	"time"
)

func benchTestDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestScaleRecordDeterministic(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	a, b := ScaleRecord(42, now), ScaleRecord(42, now)
	if a.Asset.Value != b.Asset.Value || a.Observation.PayloadHash != b.Observation.PayloadHash {
		t.Fatal("the corpus generator must be deterministic")
	}
	if a.Asset.Kind != "ip" || a.Asset.Value == "" || a.Asset.IP == nil {
		t.Fatalf("record 42 kind = %s value = %s", a.Asset.Kind, a.Asset.Value)
	}
	if a.Service == nil || a.Service.Port == 0 {
		t.Fatal("ip records must carry a service")
	}
	host := ScaleRecord(43, now)
	if host.Asset.Kind != "hostname" || host.Service != nil {
		t.Fatalf("hostname record = %+v", host)
	}
	dom := ScaleRecord(44, now)
	if dom.Asset.Kind != "domain" {
		t.Fatalf("domain record = %+v", dom)
	}
}

func TestScaleAndQualitySmallCorpus(t *testing.T) {
	ctx := context.Background()
	dir := benchTestDir(t)

	// Scale at 1x/2x with a tiny base: proves the full pipeline (payload
	// build → checksum → import → probe) runs end-to-end and reports
	// honest numbers.
	rep, err := Scale(ctx, 60, []int{1, 2}, dir)
	if err != nil {
		t.Fatalf("scale: %v", err)
	}
	if len(rep.Rows) != 2 {
		t.Fatalf("scale rows = %d, want 2", len(rep.Rows))
	}
	for i, row := range rep.Rows {
		if row.Observations != int64(60*(i+1)) {
			t.Fatalf("scale %dx ingested %d, want %d", row.Multiplier, row.Observations, 60*(i+1))
		}
		if row.WallSeconds <= 0 || row.RowsPerSec <= 0 {
			t.Fatalf("scale %dx timings not honest: %+v", row.Multiplier, row)
		}
		if row.SearchP50Ms <= 0 || row.SearchP95Ms < row.SearchP50Ms {
			t.Fatalf("scale %dx probe latencies not honest: %+v", row.Multiplier, row)
		}
		if row.DBBytes <= 0 {
			t.Fatalf("scale %dx db bytes = %d", row.Multiplier, row.DBBytes)
		}
	}

	// Quality on a small corpus: every labeled query must return
	// EXACTLY the generator's expected set (F1 = 1).
	qrep, err := Quality(ctx, 300, dir)
	if err != nil {
		t.Fatalf("quality: %v", err)
	}
	if len(qrep.Queries) != 10 {
		t.Fatalf("quality queries = %d, want 10", len(qrep.Queries))
	}
	for _, q := range qrep.Queries {
		if q.Expected == 0 {
			t.Errorf("labeled query %q has an empty expectation — the corpus must exercise every query", q.Query)
		}
		if q.F1 != 1.0 {
			t.Errorf("query %q: expected %d, returned %d, P=%.3f R=%.3f — the engine must reproduce the ground truth exactly",
				q.Query, q.Expected, q.Returned, q.Precision, q.Recall)
		}
	}
}

func TestScalePayloadManifestConsistency(t *testing.T) {
	dir := benchTestDir(t)
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	path, m, err := buildScalePayload(dir, 50, now, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = removeFileOK(path) }()
	if m.Payload.Records != 50 {
		t.Fatalf("manifest records = %d, want 50", m.Payload.Records)
	}
	if m.DatasetVersion != 7 {
		t.Fatalf("manifest version = %d, want 7", m.DatasetVersion)
	}
	if m.Payload.SizeBytes <= 0 || len(m.Payload.SHA256) != 64 {
		t.Fatalf("manifest fingerprint incomplete: %+v", m.Payload)
	}
}

func removeFileOK(path string) error { return os.Remove(path) }
