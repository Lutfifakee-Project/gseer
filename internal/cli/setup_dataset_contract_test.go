// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// setup_dataset_contract_test.go — R4 P0-4 regression battery: the
// dataset stage of `gseer setup` has an EXPLICIT contract.  A failed
// manifest fetch, signature, payload fetch, checksum, record parse, or
// import is a SETUP FAILURE (returned error, E_DATASET_SETUP_FAILED) —
// never a warning that still reports success.  The install-state
// partial failure is an explicit INTERMEDIATE state
// (E_DATASET_SETUP_STATE / dataset.ErrInstallStatePartial) with an
// idempotent recovery path.  The install state
// (dataset.LoadState — what `gseer status` / `gseer dataset status`
// report) stays truthful: NOT INSTALLED after any failed stage.
//
// The scenarios drive runDatasetAutoImport directly (the registered
// setup path calls exactly this function) against httptest channels and
// scratch personal databases — deterministic, no public network.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

// contractEnv wires one scratch setup: isolated HOME, a migrated empty
// personal database, and a personal config that points at that database
// and the given dataset channel.  Returns the db path.
func contractEnv(t *testing.T, channel string) string {
	t.Helper()
	withDatasetEnv(t)
	dbPath := newMigratedPersonalDB(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`profile: personal

database:
  dsn: %s

dataset:
  manifest_url: %s
`, yamlQuote(dbPath), yamlQuote(channel))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write contract config: %v", err)
	}
	withConfigPath(t, path)
	return dbPath
}

// runDatasetStage drives the registered dataset stage exactly as
// `gseer setup` does (same function, same config resolution).
func runDatasetStage(t *testing.T) (string, error) {
	t.Helper()
	cmd := &cobra.Command{Use: "setup"}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	err := runDatasetAutoImport(cmd, out)
	return out.String(), err
}

// serveManifestOnly serves a manifest for any request path (the payload
// fetch will see whatever bytes the manifest path returns — used for
// the payload-unavailable variant where the payload 404s).
func serveManifestOnly(t *testing.T, manifestRaw []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dataset.PayloadFilename) {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(manifestRaw)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/" + dataset.ManifestFilename
}

// deadChannel serves 404 for everything (manifest unavailable).
func deadChannel(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	return srv.URL + "/" + dataset.ManifestFilename
}

// sha256HexFor hashes payload bytes for manifest construction.
func sha256HexFor(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// testRecords returns two well-formed dataset records (one domain, one
// ip+service) — the minimal signed fixture for the contract tests.
func testRecords() []dataset.Record {
	now := time.Now().UTC().Add(-time.Minute)
	return []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset: dataset.RecordAsset{Kind: "domain", Value: "contract.example", Domain: strPtr("contract.example")},
			Observation: dataset.RecordObservation{
				Source: "central-dns", Connector: "dns", ObservedAt: now,
				PayloadHash: "sha256:contract-domain", Provenance: "dns",
			}},
		{Schema: dataset.SchemaVersion,
			Asset:   dataset.RecordAsset{Kind: "ip", Value: "93.184.216.34", IP: strPtr("93.184.216.34")},
			Service: &dataset.RecordService{Port: 443, Transport: "tcp", Protocol: "https"},
			Observation: dataset.RecordObservation{
				Source: "central-scan", Connector: "scan-tls", ObservedAt: now,
				PayloadHash: "sha256:contract-443", Provenance: "scan-tls",
			}},
	}
}

// TestDatasetSetupFailsWhenManifestUnavailable — scenario 1.
func TestDatasetSetupFailsWhenManifestUnavailable(t *testing.T) {
	dbPath := contractEnv(t, deadChannel(t))

	out, err := runDatasetStage(t)
	if err == nil {
		t.Fatalf("manifest unavailable MUST fail the setup dataset stage (warn-and-success is the R4 blocker):\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") {
		t.Errorf("expected E_DATASET_SETUP_FAILED, got: %v", err)
	}
	if !strings.Contains(err.Error(), "gseer dataset update") || !strings.Contains(err.Error(), "setup --offline") {
		t.Errorf("recovery instructions missing: %v", err)
	}
	if state, lerr := datasetStateFor(t, dbPath); lerr != nil || state.Installed {
		t.Errorf("dataset state must stay NOT INSTALLED: %v / %v", state, lerr)
	}
}

// TestDatasetSetupFailsOnInvalidSignature — scenario 2: an unverifiable
// manifest is refused, fail closed, before any payload download.
func TestDatasetSetupFailsOnInvalidSignature(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 7, recs, sha256HexFor(payload), false)
	// buildTestManifest installed the TEST keyring; an EMPTY keyring
	// makes the signature unverifiable — the production refusal path.
	dataset.SetTestKeyring(nil)
	t.Cleanup(func() { dataset.SetTestKeyring(nil) })

	dbPath := contractEnv(t, serveManifestOnly(t, raw))
	out, err := runDatasetStage(t)
	_ = dbPath
	if err == nil {
		t.Fatalf("unverifiable manifest MUST fail the dataset stage:\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") {
		t.Errorf("expected E_DATASET_SETUP_FAILED for the signature refusal, got: %v", err)
	}
}

// TestDatasetSetupFailsWhenPayloadUnavailable — scenario 3.
func TestDatasetSetupFailsWhenPayloadUnavailable(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 7, recs, sha256HexFor(payload), false)
	dbPath := contractEnv(t, serveManifestOnly(t, raw))
	out, err := runDatasetStage(t)
	_ = dbPath
	if err == nil {
		t.Fatalf("payload unavailable MUST fail the dataset stage:\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") {
		t.Errorf("expected E_DATASET_SETUP_FAILED, got: %v", err)
	}
}

// TestDatasetSetupFailsOnChecksumMismatch — scenario 4: a payload whose
// bytes do not match the manifest checksum/size is refused before
// import (the database is never touched).
func TestDatasetSetupFailsOnChecksumMismatch(t *testing.T) {
	recs := testRecords()
	wrong := payloadBytes(t, recs[:1])
	raw := buildTestManifest(t, 7, recs, sha256HexFor(wrong), false)
	full := payloadBytes(t, recs)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dataset.PayloadFilename) {
			_, _ = w.Write(full) // full payload; the manifest says otherwise
			return
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	dbPath := contractEnv(t, srv.URL+"/"+dataset.ManifestFilename)
	out, err := runDatasetStage(t)
	_ = dbPath
	if err == nil {
		t.Fatalf("checksum/size mismatch MUST fail the dataset stage:\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") {
		t.Errorf("expected E_DATASET_SETUP_FAILED, got: %v", err)
	}
	if state, lerr := datasetStateFor(t, dbPath); lerr != nil || state.Installed {
		t.Errorf("a refused payload must leave the dataset NOT INSTALLED: %v / %v", state, lerr)
	}
}

// TestDatasetSetupFailsOnInvalidRecordsAndRollsBack — scenario 5: a
// payload whose records violate the contract aborts the import; the
// database is rolled back and the stage reports failure (never
// half-installed success).
func TestDatasetSetupFailsOnInvalidRecordsAndRollsBack(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	bad := []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset: dataset.RecordAsset{Kind: "domain", Value: "bad.example", Domain: strPtr("bad.example")},
			Observation: dataset.RecordObservation{
				Source: "central-dns", Connector: "dns", ObservedAt: now,
				PayloadHash: "", Provenance: "dns", // payload_hash missing → refused
			}},
	}
	payload := payloadBytes(t, bad)
	raw := buildTestManifest(t, 8, bad, sha256HexFor(payload), false)
	dbPath := contractEnv(t, serveTestChannel(t, raw, payload))
	out, err := runDatasetStage(t)
	if err == nil {
		t.Fatalf("invalid records MUST fail the dataset stage:\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") || !strings.Contains(err.Error(), "rolled back") {
		t.Errorf("expected E_DATASET_SETUP_FAILED with rollback notice, got: %v", err)
	}
	if state, lerr := datasetStateFor(t, dbPath); lerr != nil || state.Installed {
		t.Errorf("a rolled-back import must leave the dataset NOT INSTALLED: %v / %v", state, lerr)
	}
}

// TestDatasetSetupFailsOnSQLiteImportFailure — scenario 6: an index
// that cannot accept rows (here: the observations table dropped)
// surfaces as a setup failure with a rollback, not as success.
func TestDatasetSetupFailsOnSQLiteImportFailure(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 9, recs, sha256HexFor(payload), false)
	srv := serveTestChannel(t, raw, payload)
	dbPath := contractEnv(t, srv)

	db, oerr := sql.Open("sqlite", dbPath)
	if oerr != nil {
		t.Fatalf("open scratch db: %v", oerr)
	}
	if _, derr := db.Exec(`DROP TABLE observations`); derr != nil {
		t.Fatalf("drop observations: %v", derr)
	}
	_ = db.Close()

	out, err := runDatasetStage(t)
	if err == nil {
		t.Fatalf("a broken ingestion target MUST fail the dataset stage:\n%s", out)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_FAILED") {
		t.Errorf("expected E_DATASET_SETUP_FAILED, got: %v", err)
	}
}

// TestDatasetSetupInstallStateIntermediateIsExplicit — scenario 7: when
// ingestion succeeds but the install-state recording fails (a trigger
// aborts the collection_jobs insert), the stage reports the EXPLICIT
// intermediate state (E_DATASET_SETUP_STATE, ErrInstallStatePartial)
// with the idempotent recovery instruction — never success, never a
// plain failure.
func TestDatasetSetupInstallStateIntermediateIsExplicit(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 10, recs, sha256HexFor(payload), false)
	srv := serveTestChannel(t, raw, payload)
	dbPath := contractEnv(t, srv)

	db, oerr := sql.Open("sqlite", dbPath)
	if oerr != nil {
		t.Fatalf("open scratch db: %v", oerr)
	}
	if _, derr := db.Exec(`CREATE TRIGGER r4_state_fail BEFORE INSERT ON collection_jobs
		WHEN NEW.kind = 'fetch' BEGIN SELECT RAISE(ABORT, 'injected install-state failure'); END`); derr != nil {
		t.Fatalf("create trigger: %v", derr)
	}
	_ = db.Close()

	out, err := runDatasetStage(t)
	if err == nil {
		t.Fatalf("install-state failure MUST surface as an explicit intermediate state:\n%s", out)
	}
	if !errors.Is(err, dataset.ErrInstallStatePartial) {
		t.Errorf("expected ErrInstallStatePartial, got: %v", err)
	}
	if !strings.Contains(err.Error(), "E_DATASET_SETUP_STATE") || !strings.Contains(err.Error(), "gseer dataset update") {
		t.Errorf("intermediate-state report missing code/recovery: %v", err)
	}
	if !strings.Contains(out, "[FAIL ]") || !strings.Contains(out, "install-state recording FAILED") {
		t.Errorf("output must show the explicit intermediate state:\n%s", out)
	}
}

// TestDatasetSetupRetriesAfterTemporaryNetworkFailure — scenario 8: a
// temporarily unreachable channel fails the stage; the SAME setup path
// retried afterwards succeeds (honest transient-failure behavior).
func TestDatasetSetupRetriesAfterTemporaryNetworkFailure(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 11, recs, sha256HexFor(payload), false)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dataset.ManifestFilename) {
			hits++
			if hits == 1 {
				http.Error(w, "temporary outage", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(raw)
			return
		}
		if strings.HasSuffix(r.URL.Path, dataset.PayloadFilename) {
			_, _ = w.Write(payload)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	dbPath := contractEnv(t, srv.URL+"/"+dataset.ManifestFilename)

	_, firstErr := runDatasetStage(t)
	if firstErr == nil || !strings.Contains(firstErr.Error(), "E_DATASET_SETUP_FAILED") {
		t.Fatalf("first attempt during the outage must fail with E_DATASET_SETUP_FAILED: %v", firstErr)
	}
	out, secondErr := runDatasetStage(t)
	if secondErr != nil {
		t.Fatalf("retry after the outage must succeed: %v\n%s", secondErr, out)
	}
	if !strings.Contains(out, "dataset v11 imported") {
		t.Errorf("successful retry must report the import:\n%s", out)
	}
	_ = dbPath
}

// TestDatasetSetupIdempotentRepeat — scenario 9: a second successful
// setup-stage run recognizes the installed version and does not
// double-import.
func TestDatasetSetupIdempotentRepeat(t *testing.T) {
	recs := testRecords()
	payload := payloadBytes(t, recs)
	raw := buildTestManifest(t, 12, recs, sha256HexFor(payload), false)
	srv := serveTestChannel(t, raw, payload)
	dbPath := contractEnv(t, srv)

	out1, err1 := runDatasetStage(t)
	if err1 != nil || !strings.Contains(out1, "dataset v12 imported") {
		t.Fatalf("first import: %v\n%s", err1, out1)
	}
	state1, lerr := datasetStateFor(t, dbPath)
	if lerr != nil || !state1.Installed || state1.DatasetVersion != 12 {
		t.Fatalf("state after first import: %v / %v", state1, lerr)
	}
	obs1 := observationCount(t, dbPath)

	out2, err2 := runDatasetStage(t)
	if err2 != nil {
		t.Fatalf("second stage run must succeed (idempotent): %v\n%s", err2, out2)
	}
	if !strings.Contains(out2, "already at version 12") {
		t.Errorf("the second run must recognize the installed version:\n%s", out2)
	}
	if obs2 := observationCount(t, dbPath); obs2 != obs1 {
		t.Errorf("idempotent re-run must not change the observation count: %d → %d", obs1, obs2)
	}
}

// ---------------------------------------------------------------------------
// helpers

func datasetStateFor(t *testing.T, dbPath string) (*dataset.State, error) {
	t.Helper()
	db, oerr := sql.Open("sqlite", dbPath)
	if oerr != nil {
		return nil, oerr
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return dataset.LoadState(ctx, db)
}

func observationCount(t *testing.T, dbPath string) int64 {
	t.Helper()
	db, oerr := sql.Open("sqlite", dbPath)
	if oerr != nil {
		t.Fatalf("open db: %v", oerr)
	}
	defer func() { _ = db.Close() }()
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&n); err != nil {
		t.Fatalf("count observations: %v", err)
	}
	return n
}
