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

package index

// index_test.go — the shared-index trust chain, export/import loop,
// and the HTTP end-to-end update flow.  Proven here (unit level):
//
//   1. SIGNATURE — sign→verify round trip; tampered bytes and unsigned
//      manifests are refused;
//   2. CHECKSUM — SHA-256 + size mismatches are refused;
//   3. VALIDITY — schema-ahead snapshots and count mismatches are
//      refused; truncated files fail integrity_check;
//   4. ATOMIC — the previous snapshot survives as .prev;
//   5. IMPORT — rows merge with provenance "shared-index", ids remap,
//      and re-import is a no-op (L1/L2 dedup);
//   6. UPDATE — the full flow over a real HTTP test server, including
//      the up-to-date and force paths.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// testTrustKey generates a keypair and installs the PUBLIC half as the
// test trust anchor (restored on cleanup).
func testTrustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	SetTestPublicKey(pub)
	t.Cleanup(func() { SetTestPublicKey(nil) })
	return priv
}

// newTestStore opens + migrates a fresh personal-mode store.
func newTestStore(t *testing.T) (*sqlite.Store, func()) {
	t.Helper()
	res, err := sqlite.Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		_ = res.DB.Close()
		cancel()
		t.Fatalf("migrate: %v", err)
	}
	return sqlite.NewStore(res.DB), func() { cancel(); _ = res.DB.Close() }
}

// seedSourceStore fills a store with representative pipeline data: an
// enriched IP asset, a hostname asset, a TLS service with certificate
// evidence, and two observations.
func seedSourceStore(t *testing.T, store *sqlite.Store) {
	t.Helper()
	ctx := context.Background()
	srcID, err := store.EnsureSource(ctx, "test-dns", "dns", "test terms", nil)
	if err != nil {
		t.Fatalf("ensure source: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)

	ip := "203.0.113.10"
	a1, _, err := store.UpsertAsset(ctx, &storage.Asset{
		Kind: storage.AssetKindIP, Value: ip, IP: &ip,
		ASN: 64496, ASNOrg: "EXAMPLE-AS", GeoCountry: "ID",
		Sources: []string{"dns"}, FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	host := "www.example.com"
	a2, _, err := store.UpsertAsset(ctx, &storage.Asset{
		Kind: storage.AssetKindHostname, Value: host, Hostname: &host,
		Sources: []string{"dns"}, FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	svc, _, err := store.UpsertService(ctx, &storage.Service{
		AssetID: a1, Port: 443, Transport: "tcp", Protocol: "https", Name: "https",
		FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("upsert service: %v", err)
	}
	obs := []*storage.Observation{
		{
			ID: 1, SourceID: srcID, AssetID: a1, ServiceID: &svc,
			ObservedAt: now, PayloadHash: "sha256:aaaa", SourceCursor: "v1|batch:t1|rec:0",
			Provenance: "collect",
			Evidence: map[string]any{
				"tls": map[string]any{
					"version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
					"cert_subject_cn": "www.example.com", "cert_issuer_cn": "Example CA",
					"cert_serial": "0abc123", "cert_sans_dns": []string{"www.example.com", "example.com"},
					"cert_expiry": now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
				},
			},
		},
		{
			ID: 2, SourceID: srcID, AssetID: a2,
			ObservedAt: now, PayloadHash: "sha256:bbbb", SourceCursor: "v1|batch:t1|rec:1",
			Provenance: "collect",
			Evidence:   map[string]any{"dns": map[string]any{"query": host, "type": "A"}},
		},
	}
	for _, o := range obs {
		if _, _, err := store.InsertObservation(ctx, o); err != nil {
			t.Fatalf("insert observation: %v", err)
		}
	}
}

// buildSignedChannel produces the snapshot bytes + signed manifest for
// a seeded store, with the artifact served at relPath next to the
// manifest.
func buildSignedChannel(t *testing.T, priv ed25519.PrivateKey, src *sqlite.Store, sequence int64, relPath string) (manifestBytes, artifactBytes []byte, m Manifest) {
	t.Helper()
	ctx := context.Background()
	snapPath := filepath.Join(t.TempDir(), "gseer-index-snapshot.db")
	counts, err := ExportSnapshot(ctx, src, snapPath)
	if err != nil {
		t.Fatalf("export snapshot: %v", err)
	}
	artifactBytes, err = os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	schema := 0
	{
		counts2, schema2, ierr := InspectSnapshot(ctx, snapPath)
		if ierr != nil {
			t.Fatalf("inspect snapshot: %v", ierr)
		}
		if counts2 == nil || counts2.Assets != counts.Assets {
			t.Fatalf("inspect counts mismatch: %+v vs %+v", counts2, counts)
		}
		schema = schema2
	}
	sum := sha256Hex(artifactBytes)
	m = Manifest{
		Format:        FormatVersion,
		Sequence:      sequence,
		BuiltAt:       time.Now().UTC(),
		SchemaVersion: schema,
		Counts:        *counts,
		Artifact:      Artifact{URL: relPath, SHA256: sum, Size: int64(len(artifactBytes))},
	}
	manifestBytes, err = Sign(m, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return manifestBytes, artifactBytes, m
}

func TestManifestSignVerifyRoundTrip(t *testing.T) {
	priv := testTrustKey(t)
	m := Manifest{Format: FormatVersion, Sequence: 7, BuiltAt: time.Now().UTC(),
		Counts: Counts{Assets: 1}, Artifact: Artifact{URL: "https://x/y.db", SHA256: strings.Repeat("a", 64), Size: 10}}
	signed, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := ParseManifest(signed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := parsed.VerifySignature(TrustAnchor()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tampered bytes must fail.
	parsed.Counts.Assets = 999
	if err := parsed.VerifySignature(TrustAnchor()); err == nil ||
		!strings.Contains(err.Error(), "E_INDEX_BAD_SIGNATURE") {
		t.Fatalf("tampered manifest verified: %v", err)
	}

	// Unsigned manifest must fail with the unsigned code.
	m2 := m
	m2.Signature = ""
	if err := m2.VerifySignature(TrustAnchor()); err == nil ||
		!strings.Contains(err.Error(), "E_INDEX_UNSIGNED") {
		t.Fatalf("unsigned manifest verified: %v", err)
	}
}

func TestParseManifestRejects(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"bad format", `{"format":"other/1","sequence":1}`, "cannot be read"},
		{"zero sequence", `{"format":"` + FormatVersion + `","sequence":0}`, "sequence"},
		{"short sha", `{"format":"` + FormatVersion + `","sequence":1,"artifact":{"url":"u","sha256":"ab","size":1}}`, "sha256"},
		{"missing url", `{"format":"` + FormatVersion + `","sequence":1,"artifact":{"sha256":"` + strings.Repeat("a", 64) + `","size":1}}`, "URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(c.json))
			if err == nil {
				t.Fatalf("expected rejection for %s", c.name)
			}
			if !strings.Contains(err.Error(), "E_INDEX_MALFORMED") {
				t.Fatalf("want E_INDEX_MALFORMED, got: %v", err)
			}
		})
	}
}

func TestResolveArtifactURL(t *testing.T) {
	m := Manifest{Artifact: Artifact{URL: "gseer-index-000007.db"}}
	got, err := m.ResolveArtifactURL("https://example.com/releases/download/shared-index/gseer-index-manifest.json")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := "https://example.com/releases/download/shared-index/gseer-index-000007.db"
	if got != want {
		t.Fatalf("resolved %q, want %q", got, want)
	}
	m.Artifact.URL = "https://cdn.example.com/other.db"
	got, err = m.ResolveArtifactURL("https://example.com/x.json")
	if err != nil || got != "https://cdn.example.com/other.db" {
		t.Fatalf("absolute passthrough failed: %q %v", got, err)
	}
}

func TestArtifactVerifyChecksum(t *testing.T) {
	payload := []byte("snapshot-bytes")
	sum := sha256Hex(payload)
	a := Artifact{SHA256: sum, Size: int64(len(payload))}
	if err := a.VerifyChecksum(payload); err != nil {
		t.Fatalf("valid checksum refused: %v", err)
	}
	bad := Artifact{SHA256: strings.Repeat("0", 64), Size: int64(len(payload))}
	if err := bad.VerifyChecksum(payload); err == nil ||
		!strings.Contains(err.Error(), "E_INDEX_CHECKSUM") {
		t.Fatalf("wrong checksum accepted: %v", err)
	}
	wrongSize := Artifact{SHA256: sum, Size: 999}
	if err := wrongSize.VerifyChecksum(payload); err == nil {
		t.Fatalf("wrong size accepted")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)

	snapPath := filepath.Join(t.TempDir(), "snapshot.db")
	counts, err := ExportSnapshot(ctx, src, snapPath)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if counts.Assets != 2 || counts.Services != 1 || counts.Observations != 2 {
		t.Fatalf("export counts = %+v, want 2/1/2", counts)
	}

	dst, closeDst := newTestStore(t)
	defer closeDst()
	res, err := ImportSnapshot(ctx, dst, snapPath, 1)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.AssetsInserted != 2 || res.ServicesInserted != 1 || res.ObservationsInserted != 2 {
		t.Fatalf("import stats = %+v, want 2/1/2/0/0/0", res)
	}

	// Re-import the SAME snapshot: idempotent (L1/L2 dedup).
	res2, err := ImportSnapshot(ctx, dst, snapPath, 1)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if res2.AssetsInserted != 0 || res2.ServicesInserted != 0 || res2.ObservationsInserted != 0 ||
		res2.ObservationsDeduped != 2 {
		t.Fatalf("re-import stats = %+v, want all-zero inserts with 2 deduped observations", res2)
	}

	// Provenance honesty: the client's rows carry provenance
	// "shared-index" and the asset sources list gains the label.
	var prov, sourcesJSON string
	if err := dst.DB.QueryRowContext(ctx,
		`SELECT provenance, (SELECT sources FROM assets WHERE kind='ip' LIMIT 1)
		 FROM observations ORDER BY id LIMIT 1`).Scan(&prov, &sourcesJSON); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if prov != ProvenanceSharedIndex {
		t.Fatalf("provenance = %q, want %q", prov, ProvenanceSharedIndex)
	}
	if !strings.Contains(sourcesJSON, ProvenanceSharedIndex) {
		t.Fatalf("asset sources %q lacks the %q label", sourcesJSON, ProvenanceSharedIndex)
	}

	// Evidence traveled verbatim (the fact payload is the provenance).
	var evidence string
	if err := dst.DB.QueryRowContext(ctx,
		`SELECT evidence FROM observations WHERE source_cursor LIKE 'idx:1:%' AND evidence LIKE '%cert_serial%' LIMIT 1`).Scan(&evidence); err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if !strings.Contains(evidence, "0abc123") {
		t.Fatalf("certificate serial did not travel: %s", evidence)
	}
}

func TestExportRefusesExistingOutput(t *testing.T) {
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	snapPath := filepath.Join(t.TempDir(), "snapshot.db")
	if _, err := ExportSnapshot(ctx, src, snapPath); err != nil {
		t.Fatalf("first export: %v", err)
	}
	_, err := ExportSnapshot(ctx, src, snapPath)
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_STATE") {
		t.Fatalf("second export over existing file not refused: %v", err)
	}
}

func TestUpdateEndToEndHTTP(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()

	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)

	manifestBytes, artifactBytes, _ := buildSignedChannel(t, priv, src, 7, "gseer-index-000007.db")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/gseer-index-000007.db":
			_, _ = w.Write(artifactBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()

	// 1. Check reports an update available without downloading.
	res, err := Check(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if res.UpToDate || res.RemoteSeq != 7 || res.LocalSeq != 0 {
		t.Fatalf("check result = %+v", res)
	}

	// 2. Full update: verify → download → install → import.
	res, err = Update(ctx, Options{
		ManifestURL: srv.URL + "/gseer-index-manifest.json",
		Dir:         dir,
		Store:       dst,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !res.Installed || !res.Validated || res.ImportResult == nil ||
		res.ImportResult.AssetsInserted != 2 || res.ImportResult.ObservationsInserted != 2 {
		t.Fatalf("update result = %+v", res)
	}

	// 3. The previous-snapshot file does not exist on FIRST install,
	//    and the state records sequence 7 with Imported=true.
	st, err := LoadState(dir)
	if err != nil || st == nil || st.Sequence != 7 || !st.Imported {
		t.Fatalf("state = %+v, err %v", st, err)
	}

	// 4. Second update: up-to-date, no re-install.
	res, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err != nil {
		t.Fatalf("second update: %v", err)
	}
	if !res.UpToDate || res.Installed {
		t.Fatalf("second update re-installed: %+v", res)
	}

	// 5. A NEW sequence installs atomically and keeps the previous
	//    snapshot as .prev.
	manifest2, artifact2, _ := buildSignedChannel(t, priv, src, 8, "gseer-index-000008.db")
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifest2)
		case "/gseer-index-000008.db":
			_, _ = w.Write(artifact2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv2.Close()
	res, err = Update(ctx, Options{ManifestURL: srv2.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err != nil {
		t.Fatalf("third update: %v", err)
	}
	st8, serr := LoadState(dir)
	if !res.Installed || serr != nil || st8 == nil || st8.Sequence != 8 {
		t.Fatalf("third update result/state wrong: %+v %+v %v", res, st8, serr)
	}
	if _, err := os.Stat(filepath.Join(dir, SnapshotPrev)); err != nil {
		t.Fatalf("previous snapshot not retained as .prev: %v", err)
	}
}

func TestUpdateRefusesTamperedArtifact(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	manifestBytes, artifactBytes, _ := buildSignedChannel(t, priv, src, 9, "gseer-index-000009.db")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/gseer-index-000009.db":
			tampered := append([]byte{}, artifactBytes...)
			if len(tampered) > 0 {
				tampered[len(tampered)/2] ^= 0xFF // flip one byte mid-file
			}
			_, _ = w.Write(tampered)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()
	_, err := Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_CHECKSUM") {
		t.Fatalf("tampered artifact not refused with checksum error: %v", err)
	}
	// Nothing was installed.
	if _, serr := os.Stat(filepath.Join(dir, SnapshotName)); !os.IsNotExist(serr) {
		t.Fatalf("tampered artifact was installed")
	}
}

func TestUpdateRefusesForeignSignature(t *testing.T) {
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)

	// The manifest is signed by a key the client does NOT trust.
	_, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("foreign key: %v", err)
	}
	manifestBytes, artifactBytes, _ := buildSignedChannel(t, foreignPriv, src, 10, "gseer-index-000010.db")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/gseer-index-000010.db":
			_, _ = w.Write(artifactBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()
	_, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_BAD_SIGNATURE") {
		t.Fatalf("foreign signature not refused: %v", err)
	}
}

func TestUpdateRefusesSchemaAhead(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	manifestBytes, artifactBytes, _ := buildSignedChannel(t, priv, src, 11, "gseer-index-000011.db")

	// Forge a "future" schema version INSIDE the snapshot.  The manifest
	// is re-signed so the CHECKSUM matches the manipulated bytes — the
	// SCHEMA check must be what catches this (a newer schema cannot be
	// read correctly by an older client even when every checksum agrees).
	future := int64(headVersionForTest(t) + 5)
	manipulated, err := bumpSnapshotSchema(artifactBytes, future)
	if err != nil {
		t.Fatalf("bump schema: %v", err)
	}
	{
		sum := sha256.Sum256(manipulated)
		m2 := Manifest{
			Format:        FormatVersion,
			Sequence:      11,
			BuiltAt:       time.Now().UTC(),
			SchemaVersion: headVersionForTest(t),
			Counts:        Counts{Assets: 2, Services: 1, Observations: 2},
			Artifact:      Artifact{URL: "gseer-index-000011.db", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(manipulated))},
		}
		forged, serr := Sign(m2, priv)
		if serr != nil {
			t.Fatalf("sign forged manifest: %v", serr)
		}
		manifestBytes = forged
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/gseer-index-000011.db":
			_, _ = w.Write(manipulated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()
	_, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_SCHEMA") {
		t.Fatalf("schema-ahead snapshot not refused: %v", err)
	}
}

func TestUpdateRefusesCountMismatch(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	_, artifactBytes, m := buildSignedChannel(t, priv, src, 12, "gseer-index-000012.db")

	// The manifest claims MORE assets than the artifact contains.
	m.Counts.Assets += 5
	forged, err := Sign(m, priv)
	if err != nil {
		t.Fatalf("resign: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(forged)
		case "/gseer-index-000012.db":
			_, _ = w.Write(artifactBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()
	_, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_INTEGRITY") {
		t.Fatalf("count mismatch not refused: %v", err)
	}
}

func TestValidateSnapshotRejectsTruncatedFile(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	_, artifactBytes, m := buildSignedChannel(t, priv, src, 13, "gseer-index-000013.db")
	_ = m

	bad := filepath.Join(t.TempDir(), "truncated.db")
	if err := os.WriteFile(bad, artifactBytes[:len(artifactBytes)/4], 0o600); err != nil {
		t.Fatalf("write truncated: %v", err)
	}
	err := ValidateSnapshot(ctx, bad, Counts{Assets: 2, Services: 1, Observations: 2})
	if err == nil || !strings.Contains(err.Error(), "E_INDEX_") {
		t.Fatalf("truncated snapshot not refused: %v", err)
	}
}

func TestForceReinstallAndRepairImport(t *testing.T) {
	priv := testTrustKey(t)
	ctx := context.Background()
	src, closeSrc := newTestStore(t)
	defer closeSrc()
	seedSourceStore(t, src)
	manifestBytes, artifactBytes, _ := buildSignedChannel(t, priv, src, 14, "gseer-index-000014.db")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/gseer-index-000014.db":
			_, _ = w.Write(artifactBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dst, closeDst := newTestStore(t)
	defer closeDst()

	// Install WITHOUT a store (install-only path) — Imported=false.
	res, err := Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir})
	if err != nil || !res.Installed || res.ImportResult != nil {
		t.Fatalf("install-only update = %+v err %v", res, err)
	}

	// The up-to-date branch notices the missing import and repairs it.
	res, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst})
	if err != nil {
		t.Fatalf("repair update: %v", err)
	}
	if res.ImportResult == nil || res.ImportResult.AssetsInserted != 2 {
		t.Fatalf("repair import did not run: %+v", res)
	}
	st, _ := LoadState(dir)
	if st == nil || !st.Imported {
		t.Fatalf("state not marked imported: %+v", st)
	}

	// Force re-installs the same sequence (idempotent import).
	res, err = Update(ctx, Options{ManifestURL: srv.URL + "/gseer-index-manifest.json", Dir: dir, Store: dst, Force: true})
	if err != nil || !res.Installed {
		t.Fatalf("force update: %+v err %v", res, err)
	}
}

// snapshotSchemaVersionForTest reads the schema version the way the
// client will (used by the schema-ahead forgery test).
func headVersionForTest(t *testing.T) int {
	t.Helper()
	h, err := sqlite.MigrationHead()
	if err != nil {
		t.Fatalf("migration head: %v", err)
	}
	return h
}

// bumpSnapshotSchema writes the snapshot to a temp file, sets its
// schema_migrations ledger to `version`, and returns the new bytes —
// simulating a snapshot produced by a NEWER gseer build.
func bumpSnapshotSchema(artifact []byte, version int64) ([]byte, error) {
	dir, err := os.MkdirTemp("", "gseer-bump-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "snap.db")
	if err := os.WriteFile(path, artifact, 0o600); err != nil {
		return nil, err
	}
	db, err := sqlite.Open(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := db.DB.ExecContext(ctx, `DELETE FROM schema_migrations; INSERT INTO schema_migrations (version, dirty, applied_at) VALUES (?, 0, ?)`, version, sqlite.FormatTS(time.Now().UTC())); err != nil {
		_ = db.DB.Close()
		return nil, err
	}
	_ = db.DB.Close()
	return os.ReadFile(path)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestInspectSnapshotRefusesAheadSchema pins the provider-side restore
// gate: a snapshot whose migration ledger is NEWER than this build is
// refused by InspectSnapshot (the same semantics the client's
// ValidateSnapshot enforces) — a provider must never restore a
// schema-ahead base as its working store.
func TestInspectSnapshotRefusesAheadSchema(t *testing.T) {
	ctx := context.Background()
	src, closeSrc := newTestStore(t) // migrated, empty — enough to build a valid snapshot
	defer closeSrc()
	snapPath := filepath.Join(t.TempDir(), "ahead.db")
	if _, err := ExportSnapshot(ctx, src, snapPath); err != nil {
		t.Fatalf("export snapshot: %v", err)
	}

	// Sanity: the healthy snapshot inspects clean.
	if _, _, err := InspectSnapshot(ctx, snapPath); err != nil {
		t.Fatalf("healthy snapshot must inspect clean: %v", err)
	}

	// Bump the ledger one version past this build's head → StateAhead.
	res, err := sqlite.Open(snapPath)
	if err != nil {
		t.Fatalf("open snapshot writable: %v", err)
	}
	defer func() { _ = res.DB.Close() }()
	if _, err := res.DB.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, dirty, applied_at) VALUES ((SELECT MAX(version)+1 FROM schema_migrations), 0, strftime('%s','now'))`); err != nil {
		t.Fatalf("bump ledger: %v", err)
	}
	_ = res.DB.Close()

	_, _, err = InspectSnapshot(ctx, snapPath)
	if err == nil {
		t.Fatal("schema-ahead snapshot must be refused by InspectSnapshot")
	}
	idxErr, ok := err.(*Error)
	if !ok || idxErr.Code != CodeSchema || !strings.Contains(idxErr.What, "NEWER than this build") {
		t.Fatalf("expected E_INDEX schema-ahead refusal, got: %v", err)
	}
}
