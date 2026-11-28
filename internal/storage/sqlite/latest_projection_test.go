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

package sqlite

// latest_projection_test.go — R44 regression: the maintained
// latest_http_t / latest_tls_t / latest_fingerprints_t tables (migration
// 0011) must expose the SAME winners the pre-0011 window views produced:
// newest observed_at wins, ties break on the higher observation id, and
// the latest_* views keep their column contracts (search_index reads
// them verbatim).  Also asserts the maintenance hook runs inside the
// ingest path (IngestFacts → observation insert → projection upsert).

import (
	"context"
	"database/sql"
	"hash/fnv"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func latestProjectionTestStore(t *testing.T) *Store {
	t.Helper()
	res, err := Open(t.TempDir() + "/gseer.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewStore(res.DB)
}

// ingestServiceObs is the one-fact helper: one ip asset with one https
// service (identity: asset+port+transport+protocol) and one observation
// carrying the given evidence.  The observation bookkeeping id is
// derived from the cursor exactly like the fixture/bench writers.
func ingestServiceObs(t *testing.T, st *Store, ctx context.Context, srcID int64, cursor string, at time.Time, evidence map[string]any) {
	t.Helper()
	ip := "203.0.113.10"
	f := storage.Fact{
		Asset: storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip, Sources: []string{"fixture"}},
		Service: &storage.Service{
			Port: 443, Transport: "tcp", Protocol: "https",
		},
		Observation: storage.Observation{
			SourceID: srcID, SourceCursor: cursor, PayloadHash: "hash-" + cursor,
			ObservedAt: at, Provenance: "fixture", Evidence: evidence,
		},
	}
	f.Observation.ID = observationIDForTest(cursor)
	if _, err := st.IngestFact(ctx, &f); err != nil {
		t.Fatalf("ingest %s: %v", cursor, err)
	}
}

func observationIDForTest(cursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("bench:" + cursor))
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}

func queryScalar(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	var got string
	if err := db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return got
}

func TestLatestProjectionMatchesWindowSemantics(t *testing.T) {
	st := latestProjectionTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	// Older observation first (http status 200), then newer (status 403):
	// the projection must end on the NEWEST.
	ingestServiceObs(t, st, ctx, src, "obs-a", base, map[string]any{
		"http": map[string]any{"status": 200, "title": "Old", "server": "nginx"},
	})
	ingestServiceObs(t, st, ctx, src, "obs-b", base.Add(time.Minute), map[string]any{
		"http":        map[string]any{"status": 403, "title": "New", "server": "caddy"},
		"fingerprint": map[string]any{"technologies": []string{"Caddy"}},
	})
	if got := queryScalar(t, st.DB, `SELECT status FROM latest_http_t`); got != "403" {
		t.Fatalf("latest_http_t.status = %s, want 403 (newest observation wins)", got)
	}
	if got := queryScalar(t, st.DB, `SELECT title FROM latest_http_t`); got != "New" {
		t.Fatalf("latest_http_t.title = %s, want New", got)
	}
	if got := queryScalar(t, st.DB, `SELECT technologies FROM latest_fingerprints_t`); got != `["Caddy"]` {
		t.Fatalf("latest_fingerprints_t.technologies = %s, want [\"Caddy\"]", got)
	}

	// Tie on observed_at: the higher observation id wins (same rule the
	// window views used).  Craft two cursors whose bookkeeping ids order
	// the loser first; the winner must still surface.
	c1, c2 := "tie-aaa", "tie-zzz"
	id1, id2 := observationIDForTest(c1), observationIDForTest(c2)
	if id1 == id2 {
		t.Fatal("bookkeeping id collision in test cursors")
	}
	lo, hi := c1, c2
	if id1 > id2 {
		lo, hi = c2, c1
	}
	at := base.Add(2 * time.Minute)
	ingestServiceObs(t, st, ctx, src, lo, at, map[string]any{
		"http": map[string]any{"status": 500, "title": "Loser"},
	})
	ingestServiceObs(t, st, ctx, src, hi, at, map[string]any{
		"http": map[string]any{"status": 501, "title": "Winner"},
	})
	// hi is the cursor whose bookkeeping observation id is higher; at an
	// observed_at tie it must win regardless of ingest order.
	want := "501"
	if got := queryScalar(t, st.DB, `SELECT status FROM latest_http_t`); got != want {
		t.Fatalf("tie-break: latest_http_t.status = %s, want %s (higher obs id wins)", got, want)
	}

	// The public views keep their contract: latest_http reads the table.
	if got := queryScalar(t, st.DB, `SELECT status FROM latest_http`); got != want {
		t.Fatalf("latest_http view status = %s, want %s", got, want)
	}
}

func TestLatestProjectionOlderObservationDoesNotRegress(t *testing.T) {
	st := latestProjectionTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ingestServiceObs(t, st, ctx, src, "reg-new", base, map[string]any{
		"tls": map[string]any{"version": "TLSv1.3", "cert_subject_cn": "new.example"},
	})
	ingestServiceObs(t, st, ctx, src, "reg-old", base.Add(-time.Hour), map[string]any{
		"tls": map[string]any{"version": "TLSv1.2", "cert_subject_cn": "old.example"},
	})
	if got := queryScalar(t, st.DB, `SELECT tls_version FROM latest_tls_t`); got != "TLSv1.3" {
		t.Fatalf("latest_tls_t.tls_version = %s, want TLSv1.3 (older observation must not regress)", got)
	}
	// Same for the latest_tls view (search_index's join partner).
	if got := queryScalar(t, st.DB, `SELECT tls_version FROM latest_tls`); got != "TLSv1.3" {
		t.Fatalf("latest_tls view = %s, want TLSv1.3", got)
	}
}

func TestLatestProjectionAssetOnlyObservationNoOp(t *testing.T) {
	st := latestProjectionTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	dom := "asset-only.example"
	f := storage.Fact{
		Asset: storage.Asset{Kind: storage.AssetKindDomain, Value: dom, Domain: &dom, Sources: []string{"fixture"}},
		Observation: storage.Observation{
			ID: observationIDForTest("asset-only"), SourceID: src,
			SourceCursor: "asset-only", PayloadHash: "hash-ao",
			ObservedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
			Provenance: "fixture", Evidence: map[string]any{"http": map[string]any{"status": 200}},
		},
	}
	if _, err := st.IngestFact(ctx, &f); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM latest_http_t`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("asset-only observation touched latest_http_t (%d rows), want 0", n)
	}
}

func TestLatestProjectionAssetLevelFamilies(t *testing.T) {
	st := latestProjectionTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	at := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	// ip2asn prefix on an asset-only observation (no service).
	ip := "198.51.100.9"
	f := storage.Fact{
		Asset: storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip, Sources: []string{"fixture"}},
		Observation: storage.Observation{
			ID: observationIDForTest("i2a-1"), SourceID: src,
			SourceCursor: "i2a-1", PayloadHash: "hash-i2a1", ObservedAt: at,
			Provenance: "fixture",
			Evidence:   map[string]any{"ip2asn": map[string]any{"prefix": "198.51.100.0/24"}},
		},
	}
	if _, err := st.IngestFact(ctx, &f); err != nil {
		t.Fatalf("ingest i2a: %v", err)
	}
	if got := queryScalar(t, st.DB, `SELECT prefix FROM latest_ip2asn_t`); got != "198.51.100.0/24" {
		t.Fatalf("latest_ip2asn_t.prefix = %s, want 198.51.100.0/24", got)
	}
	// The public view mirrors the table (search_index's join partner).
	if got := queryScalar(t, st.DB, `SELECT prefix FROM latest_ip2asn`); got != "198.51.100.0/24" {
		t.Fatalf("latest_ip2asn view = %s, want 198.51.100.0/24", got)
	}

	// DNS record (asset-level, $.dns object projected whole).
	dom := "dns-record.example"
	g := storage.Fact{
		Asset: storage.Asset{Kind: storage.AssetKindDomain, Value: dom, Domain: &dom, Sources: []string{"fixture"}},
		Observation: storage.Observation{
			ID: observationIDForTest("dns-1"), SourceID: src,
			SourceCursor: "dns-1", PayloadHash: "hash-dns1", ObservedAt: at,
			Provenance: "fixture",
			Evidence:   map[string]any{"dns": map[string]any{"a": "198.51.100.9", "mx": "mail.example"}},
		},
	}
	if _, err := st.IngestFact(ctx, &g); err != nil {
		t.Fatalf("ingest dns: %v", err)
	}
	if got := queryScalar(t, st.DB, `SELECT dns_record FROM latest_dns_t`); got != `{"a":"198.51.100.9","mx":"mail.example"}` {
		t.Fatalf("latest_dns_t.dns_record = %s", got)
	}

	// CT log record (asset-level, $.ctlog.* fields).
	h := storage.Fact{
		Asset: storage.Asset{Kind: storage.AssetKindHostname, Value: "ct.example", Hostname: &dom, Sources: []string{"fixture"}},
		Observation: storage.Observation{
			ID: observationIDForTest("ct-1"), SourceID: src,
			SourceCursor: "ct-1", PayloadHash: "hash-ct1", ObservedAt: at,
			Provenance: "fixture",
			Evidence: map[string]any{"ctlog": map[string]any{
				"log": "nimbus2026", "entry_type": "x509", "subject_cn": "ct.example",
				"issuer": "LE", "leaf_sha256": "abc",
			}},
		},
	}
	// fix: hostname typed field must carry the hostname value
	h.Asset.Hostname = strPtr("ct.example")
	if _, err := st.IngestFact(ctx, &h); err != nil {
		t.Fatalf("ingest ct: %v", err)
	}
	if got := queryScalar(t, st.DB, `SELECT subject_cn FROM latest_ctlog_t`); got != "ct.example" {
		t.Fatalf("latest_ctlog_t.subject_cn = %s, want ct.example", got)
	}
	if got := queryScalar(t, st.DB, `SELECT "log" FROM latest_ctlog`); got != "nimbus2026" {
		t.Fatalf("latest_ctlog view log = %s, want nimbus2026", got)
	}
}

func strPtr(s string) *string { return &s }

func TestLatestProjectionEndToEndThroughIngestFacts(t *testing.T) {
	st := latestProjectionTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	ip := "198.51.100.7"
	f := storage.Fact{
		Asset:   storage.Asset{Kind: storage.AssetKindIP, Value: ip, IP: &ip, Sources: []string{"fixture"}},
		Service: &storage.Service{Port: 80, Transport: "tcp", Protocol: "http"},
		Observation: storage.Observation{
			ID: observationIDForTest("batch-1"), SourceID: src,
			SourceCursor: "batch-1", PayloadHash: "hash-b1",
			ObservedAt: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC),
			Provenance: "fixture",
			Evidence: map[string]any{
				"http":        map[string]any{"status": 200, "title": "Batch", "server": "nginx"},
				"fingerprint": map[string]any{"technologies": []string{"nginx", "PHP"}},
			},
		},
	}
	if _, err := st.IngestFacts(ctx, []storage.Fact{f}); err != nil {
		t.Fatalf("IngestFacts: %v", err)
	}
	if got := queryScalar(t, st.DB, `SELECT title FROM latest_http_t`); got != "Batch" {
		t.Fatalf("IngestFacts path: latest_http_t.title = %q, want Batch", got)
	}
	if got := queryScalar(t, st.DB, `SELECT technologies FROM latest_fingerprints_t`); got != `["nginx","PHP"]` {
		t.Fatalf("IngestFacts path: technologies = %s, want [\"nginx\",\"PHP\"]", got)
	}
}
