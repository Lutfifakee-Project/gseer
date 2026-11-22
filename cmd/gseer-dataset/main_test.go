// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package main

// main_test.go — Rev14 publication-pipeline regression: a staging Local
// Index fed by the seed-free `ctlog` connector must produce a dataset
// artifact that (a) builds, (b) validates, and (c) carries the ctlog
// provenance + the honest NOT-internet-wide notes.  This pins the
// discovery → evidence → dataset generation chain the pipeline runs.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/collect"
	"github.com/Lutfifakee-Project/gseer/internal/dataset"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// ctPubCertTBS extracts the TBSCertificate TLV from a full DER cert.
func ctPubCertTBS(t *testing.T, der []byte) []byte {
	t.Helper()
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("outer certificate: %v", err)
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &first); err != nil {
		t.Fatalf("first certificate element: %v", err)
	}
	return first.FullBytes
}

// ctPubLeaf builds one RFC 6962 v1 leaf (TLS uint16 entry_type).
func ctPubLeaf(t *testing.T, entryType uint16, dnsNames []string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ct-publication-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if len(dnsNames) > 0 {
		tpl.DNSNames = dnsNames
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf := make([]byte, 0, 16+len(der))
	leaf = append(leaf, 0, 0)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	leaf = append(leaf, ts[:]...)
	leaf = append(leaf, byte(entryType>>8), byte(entryType))
	if entryType == 1 {
		leaf = append(leaf, make([]byte, 32)...)
		tbs := ctPubCertTBS(t, der)
		leaf = append(leaf, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		leaf = append(leaf, tbs...)
		return leaf
	}
	leaf = append(leaf, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	leaf = append(leaf, der...)
	return leaf
}

// ctPubServeLog serves a fixed RFC 6962 log over httptest.
func ctPubServeLog(t *testing.T, leaves [][]byte) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": len(leaves), "timestamp": 1794926226023})
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		var start, end int
		_, _ = fmt.Sscanf(r.URL.Query().Get("start"), "%d", &start)
		_, _ = fmt.Sscanf(r.URL.Query().Get("end"), "%d", &end)
		type entry struct {
			LeafInput string `json:"leaf_input"`
		}
		entries := []entry{}
		for i := start; i <= end && i < len(leaves); i++ {
			if i < 0 {
				break
			}
			entries = append(entries, entry{LeafInput: base64.StdEncoding.EncodeToString(leaves[i])})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + "/"
}

// TestPublicationPipelinePublishesSeedFreeCTLogEvidence — the chain the
// scheduled pipeline runs: staging index → seed-free collection →
// gseer-dataset build → validate → manifest provenance.
func TestPublicationPipelinePublishesSeedFreeCTLogEvidence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "staging.db")
	outDir := filepath.Join(dir, "dist")

	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open staging db: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := sqlite.NewStore(res.DB)

	leaves := make([][]byte, 12)
	for i := range leaves {
		leaves[i] = ctPubLeaf(t, 0, []string{fmt.Sprintf("published%d.example.org", i)})
	}
	endpoint := ctPubServeLog(t, leaves)

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

	runner := collect.NewRunner(store, collect.NewClient(collect.ClientConfig{RequestsPerSecond: 10_000, Timeout: 2 * time.Second}))
	stats, err := runner.Run(ctx, "central-ctlog")
	if err != nil {
		t.Fatalf("collect run: %v", err)
	}
	if stats.Records <= 0 || stats.Ingested <= 0 {
		t.Fatalf("seed-free collection must land evidence (got %+v)", stats)
	}

	// Publication gate: build + validate with the REAL builder code,
	// signed with an ephemeral publisher key registered as the verifier's
	// trust anchor (the same key ceremony the production ring enforces).
	seedPath, pub := writeSeedFile(t, dir)
	dataset.SetTestKeyring(dataset.Keyring{dataset.KeyID(pub): pub})
	t.Cleanup(func() { dataset.SetTestKeyring(nil) })
	opts := &buildOptions{dbPath: dbPath, outDir: outDir, version: 7, keyFile: seedPath}
	if err := runBuild(opts); err != nil {
		t.Fatalf("runBuild: %v", err)
	}
	if err := runValidate(outDir); err != nil {
		t.Fatalf("runValidate: %v", err)
	}

	manifestRaw, err := os.ReadFile(filepath.Join(outDir, "gseer-dataset-manifest.json"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	var manifest struct {
		DatasetVersion int64 `json:"dataset_version"`
		Rows           struct {
			Assets       int64 `json:"assets"`
			Observations int64 `json:"observations"`
		} `json:"rows"`
		Provenance []struct {
			Source    string `json:"source"`
			Connector string `json:"connector"`
			Records   int64  `json:"records"`
		} `json:"provenance"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("manifest json: %v", err)
	}
	if manifest.DatasetVersion != 7 {
		t.Fatalf("dataset_version = %d, want 7", manifest.DatasetVersion)
	}
	if manifest.Rows.Assets <= 0 || manifest.Rows.Observations < manifest.Rows.Assets {
		t.Fatalf("rows must carry the CT evidence (got %+v)", manifest.Rows)
	}
	found := false
	for _, p := range manifest.Provenance {
		if p.Source == "central-ctlog" && p.Connector == "ctlog" && p.Records > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("manifest provenance must include central-ctlog records (got %+v)", manifest.Provenance)
	}
	if !strings.Contains(manifest.Notes, "NOT internet-wide") || !strings.Contains(manifest.Notes, "CT-log window") {
		t.Fatalf("manifest notes must stay honest about coverage: %s", manifest.Notes)
	}
	// P0-1: the published manifest carries a signature block.
	if !strings.Contains(string(manifestRaw), `"signature"`) {
		t.Fatalf("published manifest must carry a signature block")
	}
}

// writeSeedFile materializes an ephemeral publisher seed file (0600 —
// the same contract loadSigningKey enforces) and returns its path plus
// the matching public key.
func writeSeedFile(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	path := filepath.Join(dir, "publisher.seed")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	return path, priv.Public().(ed25519.PublicKey)
}

// TestValidateRefusesUnsignedArtifact — the publisher gate is
// fail-closed: a build without a signing key produces an unsigned
// manifest and validate REFUSES it (the pipeline cannot publish).
func TestValidateRefusesUnsignedArtifact(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "staging.db")
	outDir := filepath.Join(dir, "dist")
	res, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		t.Fatal(err)
	}
	store := sqlite.NewStore(res.DB)
	if _, err := store.EnsureSource(ctx, "central-dns", "dns", "docs/SOURCES.md §C",
		map[string]any{"seed_mode": "none", "endpoint": "https://invalid.invalid"}); err != nil {
		t.Fatal(err)
	}
	// No collection needed: the artifact build gate only requires the
	// schema; use an empty-but-migrated DB and expect build to refuse —
	// instead, exercise validate on a hand-built unsigned manifest.
	manifest := map[string]any{
		"schema_version":   1,
		"dataset_version":  3,
		"generated_at_utc": time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]any{
			"filename": "gseer-dataset.ndjson.gz", "sha256": strings.Repeat("ab", 32),
			"size_bytes": 10, "records": 3,
		},
		"rows": map[string]any{"assets": 1, "services": 0, "observations": 3},
		"provenance": []map[string]any{
			{"source": "central-dns", "connector": "dns", "records": 3, "newest_observed_at": time.Now().UTC().Format(time.RFC3339)},
		},
		"freshness": map[string]any{
			"oldest_observed_at": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			"newest_observed_at": time.Now().UTC().Format(time.RFC3339),
		},
		"validator_version": "1",
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "gseer-dataset-manifest.json"), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	err = runValidate(outDir)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("unsigned artifact must be refused: %v", err)
	}
}

// TestSignRestoresValidatePass — the sign command's operation (as the
// pipeline runs it): an unsigned artifact signed with the publisher
// seed PASSES validate; a tampered manifest FAILS again.
func TestSignRestoresValidatePass(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "dist")
	// A REAL artifact: payload (2 valid records) + a manifest that
	// describes it — then the sign step, then validate.
	now := time.Now().UTC().Add(-time.Hour)
	recs := []dataset.Record{
		{Schema: 1,
			Asset:       dataset.RecordAsset{Kind: "domain", Value: "a.example.org", Domain: testStrPtr("a.example.org")},
			Observation: dataset.RecordObservation{Source: "central-dns", Connector: "dns", ObservedAt: now, PayloadHash: "sha256:t-a", Provenance: "dns"},
		},
		{Schema: 1,
			Asset:       dataset.RecordAsset{Kind: "domain", Value: "b.example.org", Domain: testStrPtr("b.example.org")},
			Observation: dataset.RecordObservation{Source: "central-dns", Connector: "dns", ObservedAt: now, PayloadHash: "sha256:t-b", Provenance: "dns"},
		},
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, rec := range recs {
		if err := enc.Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "gseer-dataset.ndjson.gz"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	manifest := map[string]any{
		"schema_version":   1,
		"dataset_version":  4,
		"generated_at_utc": time.Now().UTC().Format(time.RFC3339),
		"payload": map[string]any{
			"filename": "gseer-dataset.ndjson.gz", "sha256": hex.EncodeToString(sum[:]),
			"size_bytes": buf.Len(), "records": 2,
		},
		"rows": map[string]any{"assets": 2, "services": 0, "observations": 2},
		"provenance": []map[string]any{
			{"source": "central-dns", "connector": "dns", "records": 2, "newest_observed_at": now.Format(time.RFC3339)},
		},
		"freshness": map[string]any{
			"oldest_observed_at": now.Format(time.RFC3339),
			"newest_observed_at": now.Format(time.RFC3339),
		},
		"validator_version": "1",
	}
	raw, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(outDir, "gseer-dataset-manifest.json")
	if err := os.WriteFile(manifestPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath, pub := writeSeedFile(t, dir)
	dataset.SetTestKeyring(dataset.Keyring{dataset.KeyID(pub): pub})
	t.Cleanup(func() { dataset.SetTestKeyring(nil) })

	// sign (the same operations signCmd performs, without its os.Exit).
	key, err := loadSigningKey(seedPath)
	if err != nil {
		t.Fatalf("loadSigningKey: %v", err)
	}
	if key == nil {
		t.Fatal("signing key must resolve from the seed file")
	}
	m, err := dataset.ParseManifestUnsigned(mustRead(t, manifestPath))
	if err != nil {
		t.Fatalf("pre-sign parse: %v", err)
	}
	signed, err := dataset.SignManifest(m, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := dataset.ParseManifest(signed); err != nil {
		t.Fatalf("signed manifest must re-validate: %v", err)
	}
	if err := os.WriteFile(manifestPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runValidate(outDir); err != nil {
		t.Fatalf("signed artifact must pass validate: %v", err)
	}

	// Tamper AFTER signing: validate must refuse.
	tampered := bytes.Replace(signed, []byte(`"records": 2`), []byte(`"records": 5`), 1)
	if err := os.WriteFile(manifestPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runValidate(outDir); err == nil {
		t.Fatal("tampered signed artifact must be refused")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testStrPtr(s string) *string { return &s }
