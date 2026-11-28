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

package changes

// detect_test.go — R56/R57 regression: value changes are detected ONLY
// when a projected value actually differs; unchanged refreshes emit
// nothing; events are idempotent across re-runs; provenance rides on the
// observation that revealed the change; caller-supplied hash observation
// ids (the import/fixture pattern) are handled.

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func detectTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	res, err := sqlite.Open(t.TempDir() + "/gseer.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return sqlite.NewStore(res.DB)
}

func bookID(cursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("bench:" + cursor))
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}

// ingestOne writes one ip-asset fact with a service and evidence payload.
func ingestOne(t *testing.T, st *sqlite.Store, srcID int64, cursor string, at time.Time, evidence map[string]any) {
	t.Helper()
	ip := "203.0.113.10"
	f := storage.Fact{
		Asset:   storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip, Sources: []string{"fixture"}},
		Service: &storage.Service{Port: 443, Transport: "tcp", Protocol: "https"},
		Observation: storage.Observation{
			ID: bookID(cursor), SourceID: srcID, SourceCursor: cursor,
			PayloadHash: "hash-" + cursor, ObservedAt: at,
			Provenance: "fixture", Evidence: evidence,
		},
	}
	if _, err := st.IngestFact(context.Background(), &f); err != nil {
		t.Fatalf("ingest %s: %v", cursor, err)
	}
}

func countEvents(t *testing.T, db *sql.DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_changes WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestDetectValueChangesAndIdempotency(t *testing.T) {
	st := detectTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	// Two identical observations: only asset.new + service.new must be
	// emitted — a routine refresh of unchanged data emits NOTHING (R57).
	ingestOne(t, st, src, "obs-1", base, map[string]any{
		"http": map[string]any{"status": 200, "title": "Login", "server": "nginx"},
		"tls":  map[string]any{"version": "TLSv1.3", "cert_serial": "AA11"},
	})
	ingestOne(t, st, src, "obs-2", base.Add(time.Minute), map[string]any{
		"http": map[string]any{"status": 200, "title": "Login", "server": "nginx"},
		"tls":  map[string]any{"version": "TLSv1.3", "cert_serial": "AA11"},
	})
	st1, err := Detect(ctx, st.DB, true)
	if err != nil {
		t.Fatalf("detect 1: %v", err)
	}
	if st1.EventsEmitted != 2 {
		t.Fatalf("identical refreshes must not emit value changes: got %d events, want 2 (asset.new + service.new)", st1.EventsEmitted)
	}
	if n := countEvents(t, st.DB, `change_kind = 'http.status'`); n != 0 {
		t.Fatalf("unchanged http.status produced %d events, want 0", n)
	}

	// A genuine change: status 200 → 403, title changes, cert rotates.
	ingestOne(t, st, src, "obs-3", base.Add(2*time.Minute), map[string]any{
		"http": map[string]any{"status": 403, "title": "Denied", "server": "nginx"},
		"tls":  map[string]any{"version": "TLSv1.3", "cert_serial": "BB22"},
	})
	ingestOne(t, st, src, "obs-4", base.Add(3*time.Minute), map[string]any{
		"http": map[string]any{"status": 403, "title": "Denied", "server": "nginx"},
		"tls":  map[string]any{"version": "TLSv1.2", "cert_serial": "BB22"},
	})
	st2, err := Detect(ctx, st.DB, false)
	if err != nil {
		t.Fatalf("detect 2: %v", err)
	}
	for kind, want := range map[string]int{
		"http.status": 1, "http.title": 1, "tls.cert": 1, "tls.version": 1,
	} {
		if n := countEvents(t, st.DB, `change_kind = ?`, kind); n != want {
			t.Errorf("%s events = %d, want %d", kind, n, want)
		}
	}
	if st2.EventsEmitted != 4 {
		t.Errorf("second run emitted %d events, want 4 (status, title, cert, version)", st2.EventsEmitted)
	}
	// Provenance: the event names the observation that revealed it.
	var prov string
	if err := st.DB.QueryRow(`SELECT provenance FROM asset_changes WHERE change_kind='http.status'`).Scan(&prov); err != nil || prov != "fixture" {
		t.Errorf("http.status event provenance = %q (err %v), want fixture", prov, err)
	}
	var oldV, newV string
	_ = st.DB.QueryRow(`SELECT old_value, new_value FROM asset_changes WHERE change_kind='http.status'`).Scan(&oldV, &newV)
	if oldV != "200" || newV != "403" {
		t.Errorf("http.status event %s → %s, want 200 → 403", oldV, newV)
	}
}

func TestDetectIdempotentRerunAndHashIDs(t *testing.T) {
	st := detectTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	// obs id from the hash derivation (the import/fixture pattern — NOT
	// monotonic; the processed-set marker must handle it).
	ingestOne(t, st, src, "z-hash-1", base, map[string]any{
		"http": map[string]any{"status": 500},
	})
	s1, err := Detect(ctx, st.DB, false)
	if err != nil {
		t.Fatalf("detect 1: %v", err)
	}
	if s1.EventsEmitted != 2 { // asset.new + service.new
		t.Fatalf("first run events = %d, want 2", s1.EventsEmitted)
	}
	// Re-run: everything already processed → no work, no events.
	s2, err := Detect(ctx, st.DB, false)
	if err != nil {
		t.Fatalf("detect 2: %v", err)
	}
	if s2.EventsEmitted != 0 || s2.ObservationsScanned != 0 {
		t.Fatalf("re-run must be a no-op: events=%d scanned=%d, want 0/0", s2.EventsEmitted, s2.ObservationsScanned)
	}
	// Full rescan: re-derives the same events, inserts NOTHING new.
	s3, err := Detect(ctx, st.DB, true)
	if err != nil {
		t.Fatalf("detect 3: %v", err)
	}
	if s3.EventsEmitted != 0 {
		t.Fatalf("full rescan duplicated %d events, want 0 (UNIQUE dedup)", s3.EventsEmitted)
	}
	if n := countEvents(t, st.DB, `1=1`); n != 2 {
		t.Fatalf("total events = %d, want 2", n)
	}
}

func TestDetectAssetLevelChanges(t *testing.T) {
	st := detectTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ip := "198.51.100.9"
	mk := func(cursor string, at time.Time, prefix string) {
		f := storage.Fact{
			Asset: storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip, Sources: []string{"fixture"}},
			Observation: storage.Observation{
				ID: bookID(cursor), SourceID: src, SourceCursor: cursor,
				PayloadHash: "hash-" + cursor, ObservedAt: at,
				Provenance: "fixture",
				Evidence:   map[string]any{"ip2asn": map[string]any{"prefix": prefix}},
			},
		}
		if _, err := st.IngestFact(ctx, &f); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}
	mk("i2a-1", base, "198.51.100.0/24")
	mk("i2a-2", base.Add(time.Hour), "198.51.0.0/16") // attribution change
	if _, err := Detect(ctx, st.DB, true); err != nil {
		t.Fatalf("detect: %v", err)
	}
	var oldV, newV string
	if err := st.DB.QueryRow(`SELECT old_value, new_value FROM asset_changes WHERE change_kind='asn.prefix'`).Scan(&oldV, &newV); err != nil {
		t.Fatalf("asn.prefix event missing: %v", err)
	}
	if oldV != "198.51.100.0/24" || newV != "198.51.0.0/16" {
		t.Fatalf("asn.prefix event %s → %s, want 198.51.100.0/24 → 198.51.0.0/16", oldV, newV)
	}
}

// TestDetectSQLShape pins the SQL the detector runs against (asset
// grouping + processed-set anti-join), so a schema rename fails loudly
// here rather than silently at runtime.
func TestDetectSQLShape(t *testing.T) {
	st := detectTestStore(t)
	for _, q := range []string{
		"SELECT DISTINCT asset_id FROM observations o LEFT JOIN detect_seen s ON s.obs_id = o.id WHERE s.obs_id IS NULL ORDER BY asset_id",
		fmt.Sprintf("INSERT INTO detect_checkpoints (name, last_obs_id, updated_at) VALUES ('%s', 1, 'x') ON CONFLICT (name) DO UPDATE SET last_obs_id = 1", checkpointName),
	} {
		if _, err := st.DB.Exec(q); err != nil {
			t.Fatalf("detector SQL broken: %v\n%s", err, q)
		}
	}
}
