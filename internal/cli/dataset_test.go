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

package cli

// dataset_test.go — the central-dataset CLI acceptance (Rev 9): update
// imports the downloaded dataset into the Local Index (search finds it),
// a tampered payload is refused with the database untouched, an
// unreachable channel degrades honestly, and `gseer setup` auto-imports.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

// serveTestDataset spins a loopback channel serving a manifest + payload
// built from records (http on loopback is the allowed local-testing
// transport) and returns the manifest URL.
func serveTestDataset(t *testing.T, version int64, recs []dataset.Record) string {
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
	now := time.Now().UTC().Add(-time.Minute)
	m := &dataset.Manifest{
		SchemaVersion:  dataset.SchemaVersion,
		DatasetVersion: version,
		GeneratedAtUTC: now,
		Payload: dataset.PayloadInfo{
			Filename:  dataset.PayloadFilename,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: int64(buf.Len()),
			Records:   int64(len(recs)),
		},
		Rows:             dataset.RowsInfo{Assets: int64(len(recs)), Services: int64(len(recs)) / 2, Observations: int64(len(recs))},
		Provenance:       []dataset.ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: int64(len(recs))}, {Source: "central-scan", Connector: "scan-tls", Records: 1}},
		Freshness:        dataset.FreshnessInfo{OldestObservedAt: now.Add(-time.Second), NewestObservedAt: now},
		ValidatorVersion: "1",
		Notes:            "test dataset (unit acceptance)",
	}
	manifestRaw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, dataset.ManifestFilename):
			_, _ = w.Write(manifestRaw)
		case strings.HasSuffix(r.URL.Path, dataset.PayloadFilename):
			_, _ = w.Write(buf.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/" + dataset.ManifestFilename
}

// withDatasetEnv isolates HOME/GSEER_HOME for one dataset test.
func withDatasetEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GSEER_HOME", home)
	return home
}

func TestDatasetUpdateImportsAndSearchFindsIt(t *testing.T) {
	home := withDatasetEnv(t)
	resetSetupFlags(t)

	now := time.Now().UTC().Add(-time.Minute)
	recs := []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset: dataset.RecordAsset{Kind: "domain", Value: "example.com", Domain: strPtr("example.com")},
			Observation: dataset.RecordObservation{
				Source: "central-dns", Connector: "dns", ObservedAt: now,
				PayloadHash: "sha256:cli-test-domain", Provenance: "dns",
				Evidence: map[string]any{"note": "unit acceptance"},
			}},
		{Schema: dataset.SchemaVersion,
			Asset:   dataset.RecordAsset{Kind: "ip", Value: "93.184.216.34", IP: strPtr("93.184.216.34")},
			Service: &dataset.RecordService{Port: 443, Transport: "tcp", Protocol: "https"},
			Observation: dataset.RecordObservation{
				Source: "central-scan", Connector: "scan-tls", ObservedAt: now,
				PayloadHash: "sha256:cli-test-443", Provenance: "scan-tls",
				Evidence: map[string]any{"tls_version": "TLS 1.3"},
			}},
	}
	channel := serveTestDataset(t, 42, recs)

	out := &bytes.Buffer{}
	cmd, _, err := RootCmd.Find([]string{"dataset", "update"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetOut(out)
	if err := cmd.Flags().Set("manifest-url", channel); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("dataset update: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "dataset v42 imported") {
		t.Fatalf("update output missing the import line:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "suppressed by YOUR rules") {
		t.Fatalf("update output missing the honesty line:\n%s", out.String())
	}

	// The journey: search port=443 must now return the DATASET row
	// (search stays local; it never probed anything).
	searchCmd, _, err := RootCmd.Find([]string{"search"})
	if err != nil {
		t.Fatal(err)
	}
	searchOut := &bytes.Buffer{}
	searchCmd.SetOut(searchOut)
	if err := searchCmd.RunE(searchCmd, []string{"port=443"}); err != nil {
		t.Fatalf("search: %v\n%s", err, searchOut.String())
	}
	if !strings.Contains(searchOut.String(), "93.184.216.34") || !strings.Contains(searchOut.String(), ":443") {
		t.Fatalf("search port=443 must return the imported dataset row:\n%s", searchOut.String())
	}
	_ = home
}

func TestDatasetUpdateChecksumFailureLeavesDBUntouched(t *testing.T) {
	withDatasetEnv(t)
	resetSetupFlags(t)

	recs := []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset: dataset.RecordAsset{Kind: "domain", Value: "example.net", Domain: strPtr("example.net")},
			Observation: dataset.RecordObservation{
				Source: "central-dns", Connector: "dns", ObservedAt: time.Now().UTC(),
				PayloadHash: "sha256:x", Provenance: "dns",
			}},
	}
	_ = serveTestDataset(t, 43, recs) // not used directly; the tampered channel below is

	// Provision the personal engine first (so the DB exists and its row
	// counts are measurable), then tamper the SERVED payload.
	out := &bytes.Buffer{}
	setupCmd, _, err := RootCmd.Find([]string{"setup"})
	if err != nil {
		t.Fatal(err)
	}
	setupCmd.SetOut(out)
	_ = setupCmd.Flags().Set("personal", "true")
	if err := setupCmd.RunE(setupCmd, nil); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}
	dbPath := defaultPersonalDBPath()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// Tamper: serve a manifest that advertises a WRONG checksum for the
	// real payload (the served payload stays valid gzip; the manifest
	// lies).  The fetcher must refuse at the checksum gate.
	tampered := serveTamperedDataset(t, 44, recs)

	out2 := &bytes.Buffer{}
	cmd, _, err := RootCmd.Find([]string{"dataset", "update"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetOut(out2)
	_ = cmd.Flags().Set("manifest-url", tampered)

	guard := pinExitFunc(t)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("update returned an error (must exit via the seam): %v", err)
	}
	if guard.called == nil || *guard.called != ExitInvalidInput {
		t.Fatalf("checksum failure must exit 2 via the seam, got called=%v", guard.called)
	}
	if !strings.Contains(out2.String(), "E_DATASET_CHECKSUM") {
		t.Fatalf("output must name the checksum refusal:\n%s", out2.String())
	}
	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the refused import touched the database: %d → %d", before, after)
	}
}

// serveTamperedDataset serves a manifest whose payload checksum does not
// match the payload it serves (simulating corruption/tamper).
func serveTamperedDataset(t *testing.T, version int64, recs []dataset.Record) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	_ = gz.Close()
	now := time.Now().UTC().Add(-time.Minute)
	m := &dataset.Manifest{
		SchemaVersion:  dataset.SchemaVersion,
		DatasetVersion: version,
		GeneratedAtUTC: now,
		Payload: dataset.PayloadInfo{
			Filename:  dataset.PayloadFilename,
			SHA256:    strings.Repeat("de", 32), // a lie
			SizeBytes: int64(buf.Len()),
			Records:   int64(len(recs)),
		},
		Rows:             dataset.RowsInfo{Assets: int64(len(recs)), Services: 0, Observations: int64(len(recs))},
		Provenance:       []dataset.ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: int64(len(recs))}},
		Freshness:        dataset.FreshnessInfo{OldestObservedAt: now, NewestObservedAt: now},
		ValidatorVersion: "1",
	}
	manifestRaw, _ := json.Marshal(m)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, dataset.ManifestFilename) {
			_, _ = w.Write(manifestRaw)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/" + dataset.ManifestFilename
}

func TestDatasetUpdateUnreachableHonest(t *testing.T) {
	withDatasetEnv(t)
	resetSetupFlags(t)

	// Dead channel: provision first (no dataset network in provisioning),
	// then update against a closed server.
	out := &bytes.Buffer{}
	setupCmd, _, _ := RootCmd.Find([]string{"setup"})
	setupCmd.SetOut(out)
	_ = setupCmd.Flags().Set("personal", "true")
	if err := setupCmd.RunE(setupCmd, nil); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	out2 := &bytes.Buffer{}
	cmd, _, _ := RootCmd.Find([]string{"dataset", "update"})
	cmd.SetOut(out2)
	_ = cmd.Flags().Set("manifest-url", deadURL+"/gseer-dataset-manifest.json")
	guard := pinExitFunc(t)
	_ = cmd.RunE(cmd, nil)
	if guard.called == nil || *guard.called != ExitUnavailable {
		t.Fatalf("unreachable must exit 4 via the seam, got called=%v", guard.called)
	}
	if !strings.Contains(out2.String(), "E_DATASET_UNREACHABLE") {
		t.Fatalf("output must name the unreachability honestly:\n%s", out2.String())
	}
}

// TestDatasetSetupAutoImports pins the journey: a provisioned personal
// engine + `gseer setup` (refresh path) imports the dataset and the
// LOCAL search finds the imported port=443 row — no manual seed, no
// manual collect, no manual scan in the user's install.
func TestDatasetSetupAutoImports(t *testing.T) {
	withDatasetEnv(t)
	resetSetupFlags(t)

	now := time.Now().UTC().Add(-time.Minute)
	recs := []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset:   dataset.RecordAsset{Kind: "ip", Value: "198.51.100.7", IP: strPtr("198.51.100.7")},
			Service: &dataset.RecordService{Port: 443, Transport: "tcp", Protocol: "https"},
			Observation: dataset.RecordObservation{
				Source: "central-scan", Connector: "scan-tls", ObservedAt: now,
				PayloadHash: "sha256:setup-journey", Provenance: "scan-tls",
				Evidence: map[string]any{"tls_version": "TLS 1.3"},
			}},
	}
	channel := serveTestDataset(t, 7, recs)
	t.Setenv("GSEER_DATASET_MANIFEST_URL", channel)

	// Provision personal mode the way the zero-config path does (the
	// egress-bootstrap stage is exercised separately; the dataset stage
	// must be independent of it — offline setups still get the dataset).
	out := &bytes.Buffer{}
	setupCmd, _, _ := RootCmd.Find([]string{"setup"})
	setupCmd.SetOut(out)
	_ = setupCmd.Flags().Set("personal", "true")
	if err := setupCmd.RunE(setupCmd, nil); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}

	cfg, cfgErr := loadEngineConfig()
	if cfgErr != nil {
		t.Fatalf("engine config: %v", cfgErr)
	}
	runDatasetAutoImport(setupCmd, out)
	if !strings.Contains(out.String(), "dataset v7 imported") {
		t.Fatalf("setup output missing the dataset import line:\n%s", out.String())
	}

	// The local search finds the dataset row.
	searchCmd, _, _ := RootCmd.Find([]string{"search"})
	searchOut := &bytes.Buffer{}
	searchCmd.SetOut(searchOut)
	if err := searchCmd.RunE(searchCmd, []string{"port=443"}); err != nil {
		t.Fatalf("search: %v\n%s", err, searchOut.String())
	}
	if !strings.Contains(searchOut.String(), "198.51.100.7") {
		t.Fatalf("search must return the dataset row after setup:\n%s", searchOut.String())
	}
	_ = cfg
}

func strPtr(s string) *string { return &s }
