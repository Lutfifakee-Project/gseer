// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gseer.db")
	res, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.DB.Close() }()
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return path
}

func mustManifest(t *testing.T, raw []byte) *Manifest {
	t.Helper()
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

// writeTestDataset writes payload + manifest for the given records into
// dir and returns the manifest.
func writeTestDataset(t *testing.T, dir string, version int64, recs []Record) *Manifest {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	assets := map[string]bool{}
	services := int64(0)
	for _, r := range recs {
		assets[r.Asset.Kind+"|"+r.Asset.Value] = true
		if r.Service != nil {
			services++
		}
	}
	var oldest, newest time.Time
	perSource := map[string]*ProvenanceSummary{}
	for _, r := range recs {
		if oldest.IsZero() || r.Observation.ObservedAt.Before(oldest) {
			oldest = r.Observation.ObservedAt
		}
		if newest.IsZero() || r.Observation.ObservedAt.After(newest) {
			newest = r.Observation.ObservedAt
		}
		p := perSource[r.Observation.Source]
		if p == nil {
			p = &ProvenanceSummary{Source: r.Observation.Source, Connector: r.Observation.Connector, NewestObservedAt: r.Observation.ObservedAt}
			perSource[r.Observation.Source] = p
		}
		p.Records++
		if r.Observation.ObservedAt.After(p.NewestObservedAt) {
			p.NewestObservedAt = r.Observation.ObservedAt
		}
	}
	m := &Manifest{
		SchemaVersion:  SchemaVersion,
		DatasetVersion: version,
		GeneratedAtUTC: time.Now().UTC(),
		Payload: PayloadInfo{
			Filename:  PayloadFilename,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: int64(buf.Len()),
			Records:   int64(len(recs)),
		},
		Rows:             RowsInfo{Assets: int64(len(assets)), Services: services, Observations: int64(len(recs))},
		Freshness:        FreshnessInfo{OldestObservedAt: oldest, NewestObservedAt: newest},
		ValidatorVersion: "1",
	}
	for _, p := range perSource {
		m.Provenance = append(m.Provenance, *p)
	}
	// P0-1: the test channel publishes SIGNED manifests (TestMain
	// installs the ephemeral suite keyring) — the same fail-closed path
	// production bytes take.
	if err := m.ValidateCore(); err != nil {
		t.Fatalf("test manifest invalid: %v", err)
	}
	signed, err := SignManifest(m, testPriv)
	if err != nil {
		t.Fatalf("sign test manifest: %v", err)
	}
	m, err = ParseManifest(signed)
	if err != nil {
		t.Fatalf("signed test manifest does not re-parse: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, PayloadFilename), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return m
}

func domainRec(source string, at time.Time, domain string) Record {
	return Record{
		Schema: SchemaVersion,
		Asset:  RecordAsset{Kind: "domain", Value: domain, Domain: strPtr(domain)},
		Observation: RecordObservation{
			Source:      source,
			Connector:   "dns",
			ObservedAt:  at.UTC(),
			PayloadHash: "sha256:test-" + domain + "-" + source,
			Provenance:  "dns",
			Evidence:    map[string]any{"note": "test record"},
		},
	}
}

func serviceRec(source string, at time.Time, ip string, port int) Record {
	return Record{
		Schema: SchemaVersion,
		Asset:  RecordAsset{Kind: "ip", Value: ip, IP: strPtr(ip)},
		Service: &RecordService{
			Port: port, Transport: "tcp", Protocol: "https",
		},
		Observation: RecordObservation{
			Source:      source,
			Connector:   "scan-tls",
			ObservedAt:  at.UTC(),
			PayloadHash: "sha256:test-" + ip + "-" + fmt.Sprint(port),
			Provenance:  "scan-tls",
			Evidence:    map[string]any{"tls_version": "TLS 1.3", "subject_cn": "example.com"},
		},
	}
}

func strPtr(s string) *string { return &s }

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// manifest
// ---------------------------------------------------------------------------

func TestManifestValidate(t *testing.T) {
	good := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   7,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 2, Services: 1, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().Add(-time.Hour), NewestObservedAt: time.Now()},
		ValidatorVersion: "1",
		// Signature SHAPE is validated here (crypto in VerifyTrusted —
		// sign_test.go): a well-formed 64-byte Ed25519 signature block.
		Signature: &ManifestSignature{
			Algorithm: SignatureAlgorithm,
			KeyID:     EmbeddedDatasetKeyID,
			Value:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good manifest refused: %v", err)
	}

	bad := []*Manifest{}
	for _, mutate := range []func(m *Manifest){
		func(m *Manifest) { m.SchemaVersion = SchemaVersion + 1 },
		func(m *Manifest) { m.DatasetVersion = 0 },
		func(m *Manifest) { m.Payload.SHA256 = "not-hex" },
		func(m *Manifest) { m.Payload.Records = 4 },
		func(m *Manifest) { m.Provenance = nil },
		func(m *Manifest) {
			m.Freshness.OldestObservedAt, m.Freshness.NewestObservedAt = m.Freshness.NewestObservedAt, m.Freshness.OldestObservedAt
		},
		func(m *Manifest) { m.ValidatorVersion = "" },
		func(m *Manifest) { m.Payload.Filename = "evil.bin" },
		// P0-1: signature-shape mutations are refusals too.
		func(m *Manifest) { m.Signature = nil },
		func(m *Manifest) { m.Signature.Algorithm = "rsa2048" },
		func(m *Manifest) { m.Signature.KeyID = "" },
		func(m *Manifest) { m.Signature.Value = "not-base64!!!" },
	} {
		m2 := *good
		mutate(&m2)
		bad = append(bad, &m2)
	}
	for i, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("mutated manifest %d accepted", i)
		}
	}
}

func TestValidateManifestURL(t *testing.T) {
	for _, ok := range []string{
		"https://github.com/example/gseer/releases/download/central-dataset/gseer-dataset-manifest.json",
		"http://127.0.0.1:8080/gseer-dataset-manifest.json",
		"http://localhost:9000/manifest.json",
	} {
		if err := ValidateManifestURL(ok); err != nil {
			t.Errorf("url %q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://example.com/manifest.json", // plaintext to a non-local host
		"ftp://example.com/manifest.json",
		"not a url",
		"",
	} {
		if err := ValidateManifestURL(bad); err == nil {
			t.Errorf("url %q accepted", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

func TestFetcherChecksumMismatch(t *testing.T) {
	records := []Record{domainRec("central-dns", time.Now().Add(-time.Minute), "example.com")}
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 1, records)
	payloadRaw, err := os.ReadFile(filepath.Join(dir, PayloadFilename))
	if err != nil {
		t.Fatal(err)
	}
	// Serve a manifest whose checksum describes DIFFERENT bytes: the
	// fetcher must refuse before any database is touched.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ManifestFilename) {
			raw, _ := json.Marshal(m)
			_, _ = w.Write(raw)
			return
		}
		// Same SIZE, different bytes: the size gate passes, the
		// checksum gate must catch the tamper.
		tampered := make([]byte, len(payloadRaw))
		copy(tampered, payloadRaw)
		tampered[len(tampered)-1] ^= 0xFF
		_, _ = w.Write(tampered)
	}))
	defer srv.Close()

	f := NewFetcher()
	manifest, err := f.FetchManifest(context.Background(), srv.URL+"/"+ManifestFilename)
	if err != nil {
		t.Fatalf("manifest fetch: %v", err)
	}
	if _, err := f.FetchPayload(context.Background(), srv.URL+"/"+ManifestFilename, manifest); err == nil {
		t.Fatal("tampered payload accepted")
	} else if !strings.Contains(err.Error(), "E_DATASET_CHECKSUM") {
		t.Fatalf("checksum error must carry the code: %v", err)
	}
}

func TestFetcherUnreachable(t *testing.T) {
	// A dead port on loopback: connection refused, honest error code.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now dead

	_, err := NewFetcher().FetchManifest(context.Background(), url+"/gseer-dataset-manifest.json")
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_UNREACHABLE") {
		t.Fatalf("want E_DATASET_UNREACHABLE, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

func TestImportHappyPathAndIdempotency(t *testing.T) {
	dbPath := newTestDB(t)
	now := time.Now().UTC().Add(-time.Minute)
	recs := []Record{
		domainRec("central-dns", now, "example.com"),
		domainRec("central-dns", now, "example.net"),
		serviceRec("central-scan", now.Add(-30*time.Second), "93.184.216.34", 443),
	}
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 11, recs)

	res, err := Import(context.Background(), ImportOptions{
		DBPath:      dbPath,
		PayloadPath: filepath.Join(dir, PayloadFilename),
		Manifest:    m,
		ManifestURL: "http://127.0.0.1/manifest.json",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Stats.ObservationsInserted != 3 {
		t.Errorf("observations inserted = %d, want 3", res.Stats.ObservationsInserted)
	}
	if res.Recovered {
		t.Error("recovered must be false on a clean import")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if got := rowCount(t, db, "observations"); got != 3 {
		t.Errorf("observations rows = %d, want 3", got)
	}
	if got := rowCount(t, db, "services"); got != 1 {
		t.Errorf("services rows = %d, want 1", got)
	}
	// Provenance: dataset-imported observations carry their collector
	// source registry rows (disabled) and the dataset channel marker.
	var conn, enabled string
	if err := db.QueryRow(`SELECT connector, enabled FROM data_sources WHERE name = 'central-scan'`).Scan(&conn, &enabled); err != nil {
		t.Fatalf("source row missing: %v", err)
	}
	if conn != "scan-tls" || enabled != "0" {
		t.Errorf("dataset source row = (%s, %s), want (scan-tls, 0)", conn, enabled)
	}
	var evidence string
	if err := db.QueryRow(`SELECT evidence FROM observations WHERE payload_hash = ?`,
		"sha256:test-93.184.216.34-443").Scan(&evidence); err != nil {
		t.Fatalf("observation missing: %v", err)
	}
	if !strings.Contains(evidence, "dataset_version") || !strings.Contains(evidence, "11") {
		t.Errorf("evidence must carry the dataset_version marker: %s", evidence)
	}

	// Install state recorded and readable.
	state, err := LoadState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Installed || state.DatasetVersion != 11 || state.Records != 3 {
		t.Errorf("state = %+v, want installed v11 with 3 records", state)
	}

	// Idempotent re-import of the SAME dataset version: everything
	// dedupes, no duplicates land.
	res2, err := Import(context.Background(), ImportOptions{
		DBPath:      dbPath,
		PayloadPath: filepath.Join(dir, PayloadFilename),
		Manifest:    m,
		ManifestURL: "http://127.0.0.1/manifest.json",
	})
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if res2.Stats.ObservationsInserted != 0 || res2.Stats.ObservationsDeduped != 3 {
		t.Errorf("re-import stats = %+v, want 0 inserted / 3 deduped", res2.Stats)
	}
	if got := rowCount(t, db, "observations"); got != 3 {
		t.Errorf("observations after re-import = %d, want 3", got)
	}
}

// TestImportSelfProvisionsFreshDatabase — the dataset stage is a
// WRITER: it must work even when the Local Index file has never been
// provisioned.  Bare `gseer setup` with an existing config whose
// database.dsn was never provisioned reaches the import through the
// refresh tail with an empty (zero-byte, table-less) file — the import
// must provision the schema itself (Open + idempotent Migrate) instead
// of failing on "no such table".  Regression for the R7 end-to-end
// finding.
func TestImportSelfProvisionsFreshDatabase(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	recs := []Record{domainRec("central-dns", now, "example.com")}
	for _, tc := range []struct {
		name string
		pre  func(t *testing.T, path string)
	}{
		{"missing file", func(t *testing.T, path string) {}},
		{"empty zero-byte file", func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "fresh.db")
			tc.pre(t, dbPath)
			m := writeTestDataset(t, dir, 12, recs)
			res, err := Import(context.Background(), ImportOptions{
				DBPath:      dbPath,
				PayloadPath: filepath.Join(dir, PayloadFilename),
				Manifest:    m,
				ManifestURL: "http://127.0.0.1/manifest.json",
			})
			if err != nil {
				t.Fatalf("import into a non-provisioned database: %v", err)
			}
			if res.Stats.ObservationsInserted != 1 {
				t.Errorf("observations inserted = %d, want 1", res.Stats.ObservationsInserted)
			}
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			state, err := LoadState(context.Background(), db)
			if err != nil {
				t.Fatal(err)
			}
			if !state.Installed || state.DatasetVersion != 12 || state.Records != 1 {
				t.Errorf("state = %+v, want installed v12 with 1 record", state)
			}
		})
	}
}

func TestImportRollbackOnBadRecord(t *testing.T) {
	dbPath := newTestDB(t)
	now := time.Now().UTC().Add(-time.Minute)
	good := []Record{
		domainRec("central-dns", now, "example.com"),
		serviceRec("central-scan", now, "93.184.216.34", 443),
	}
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 3, good)
	payloadPath := filepath.Join(dir, PayloadFilename)

	// First import lands.
	if _, err := Import(context.Background(), ImportOptions{DBPath: dbPath, PayloadPath: payloadPath, Manifest: m}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeObs := rowCount(t, db, "observations")
	beforeSvc := rowCount(t, db, "services")

	// A second payload whose LAST record is malformed (bad port): the
	// import must refuse and leave the database byte-for-byte at the
	// pre-import state (rollback), not partially applied.
	bad := []Record{
		domainRec("central-dns", now, "example.org"),
		{Schema: SchemaVersion,
			Asset:   RecordAsset{Kind: "ip", Value: "192.0.2.9", IP: strPtr("192.0.2.9")},
			Service: &RecordService{Port: 0, Transport: "tcp", Protocol: "https"}, // invalid
			Observation: RecordObservation{
				Source: "central-scan", Connector: "scan-tls",
				ObservedAt: now, PayloadHash: "sha256:bad-port", Provenance: "scan-tls",
			}},
	}
	m2 := writeTestDataset(t, dir, 4, bad)
	if _, ierr := Import(context.Background(), ImportOptions{DBPath: dbPath, PayloadPath: payloadPath, Manifest: m2}); ierr == nil {
		t.Fatal("bad-record import accepted")
	} else if !strings.Contains(ierr.Error(), "rolled back") {
		t.Fatalf("unexpected failure mode (want clean rollback): %v", ierr)
	}
	afterObs := rowCount(t, db, "observations")
	afterSvc := rowCount(t, db, "services")
	if afterObs != beforeObs || afterSvc != beforeSvc {
		t.Fatalf("rollback failed: observations %d→%d, services %d→%d", beforeObs, afterObs, beforeSvc, afterSvc)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations WHERE payload_hash = 'sha256:test-example.org-central-dns'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("the refused record's data leaked into the database")
	}
	if _, err := os.Stat(dbPath + ImportMarkerSuffix); !os.IsNotExist(err) {
		t.Errorf("snapshot cleanup missing after rollback: %v", err)
	}
}

func TestImportRecoveryAfterInterruption(t *testing.T) {
	dbPath := newTestDB(t)
	now := time.Now().UTC().Add(-time.Minute)
	recs := []Record{domainRec("central-dns", now, "example.com")}
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 9, recs)

	// Simulate an interrupted import: a leftover snapshot from a run
	// that died between snapshot and commit.
	snapshot := dbPath + ImportMarkerSuffix
	if _, err := Import(context.Background(), ImportOptions{DBPath: dbPath, PayloadPath: filepath.Join(dir, PayloadFilename), Manifest: m}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	// Roll the file back to a copy WITHOUT the import (pre-import state).
	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	orig := filepath.Join(dir, "orig.db")
	if _, err := res.DB.Exec("VACUUM INTO ?", orig); err != nil {
		t.Fatal(err)
	}
	_ = res.DB.Close()
	if err := copyFile(orig, dbPath); err != nil {
		t.Fatal(err)
	}
	// Now leave a "snapshot" behind (the interrupted-import marker).
	if err := copyFile(orig, snapshot); err != nil {
		t.Fatal(err)
	}

	res2, err := Import(context.Background(), ImportOptions{DBPath: dbPath, PayloadPath: filepath.Join(dir, PayloadFilename), Manifest: m})
	if err != nil {
		t.Fatalf("import with recovery: %v", err)
	}
	if !res2.Recovered {
		t.Error("Recovered must be true when a leftover snapshot was restored")
	}
	if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
		t.Errorf("snapshot not cleaned after successful import: %v", err)
	}
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o600)
}
