// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// sign_test.go — the P0-1 signature suite: every acceptance case of the
// signed dataset distribution is pinned here.  All keys are EPHEMERAL,
// generated in-process (TestMain) — no signing key ever ships in the
// test code, and the production embedded anchor has its own consistency
// test (TestEmbeddedAnchorConsistency).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testPriv/testPub are the suite's ephemeral publisher keys; TestMain
// installs them as the trust anchor for every test in this package.
var (
	testPriv ed25519.PrivateKey
	testPub  ed25519.PublicKey
)

func TestMain(m *testing.M) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	testPub, testPriv = pub, priv
	SetTestKeyring(Keyring{KeyID(testPub): testPub})
	code := m.Run()
	// Clear the override so no other package in this binary inherits it.
	SetTestKeyring(nil)
	os.Exit(code)
}

// signedManifest signs m with the suite key and re-parses it through
// the STRICT ParseManifest (the same path production bytes take).
func signedManifest(t *testing.T, m *Manifest) *Manifest {
	t.Helper()
	raw, err := SignManifest(m, testPriv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return mustManifest(t, raw)
}

// ---------------------------------------------------------------------------
// acceptance: valid signature PASSes end to end
// ---------------------------------------------------------------------------

func TestSignVerifyRoundtrip(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   42,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 2, Services: 1, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	signed := signedManifest(t, m)
	if err := VerifyTrusted(signed); err != nil {
		t.Fatalf("valid signature refused: %v", err)
	}
	if signed.Signature.KeyID != KeyID(testPub) {
		t.Errorf("signature key_id = %s, want %s", signed.Signature.KeyID, KeyID(testPub))
	}
	// Canonical-core determinism: re-marshaling the signed manifest minus
	// its signature reproduces the exact bytes that were signed.
	core, err := signed.CanonicalCore()
	if err != nil {
		t.Fatal(err)
	}
	unsignedCore, err := m.CanonicalCore()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(core, unsignedCore) {
		t.Fatal("canonical core is not deterministic across sign/verify")
	}
}

func TestEmbeddedAnchorConsistency(t *testing.T) {
	// The PRODUCTION trust anchor must be internally consistent: the
	// embedded public key decodes, and its derived key ID equals the
	// embedded key ID.  A broken constant pair must fail the build, not
	// ship a CLI that refuses every manifest.
	kr := defaultKeyring()
	pub, ok := kr[EmbeddedDatasetKeyID]
	if !ok {
		t.Fatalf("embedded keyring lacks key %s", EmbeddedDatasetKeyID)
	}
	if got := KeyID(pub); got != EmbeddedDatasetKeyID {
		t.Fatalf("embedded key_id %s does not match KeyID(pub) = %s — fix the constants", EmbeddedDatasetKeyID, got)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("embedded public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

// ---------------------------------------------------------------------------
// acceptance: fail-closed cases
// ---------------------------------------------------------------------------

func TestUnsignedManifestRefusedEverywhere(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   1,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("unsigned manifest accepted by Validate: %v", err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(raw); err == nil || !strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("unsigned manifest accepted by ParseManifest: %v", err)
	}
	if _, err := Import(context.Background(), ImportOptions{
		DBPath:      newTestDB(t),
		PayloadPath: "unused.ndjson.gz",
		Manifest:    m,
	}); err == nil || !strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("unsigned manifest accepted by Import: %v", err)
	}
	// Fetch path: a channel serving an unsigned manifest is refused
	// BEFORE the payload exists.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	if _, err := NewFetcher().FetchManifest(context.Background(), srv.URL+"/"+ManifestFilename); err == nil ||
		!strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("fetch of unsigned manifest accepted: %v", err)
	}
}

func TestPayloadTamperRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   2,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	signed := signedManifest(t, m)
	// Flip ONE byte of the payload identity the signature binds.
	signed.Payload.SHA256 = strings.Repeat("cd", 32)
	if err := VerifyTrusted(signed); err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
		t.Fatalf("payload-tampered manifest accepted: %v", err)
	}
}

func TestManifestTamperRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   3,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	signed := signedManifest(t, m)
	// Manifest-level tampers: version bump, record count, provenance,
	// freshness — each must break the signature.
	for name, mutate := range map[string]func(*Manifest){
		"dataset_version": func(x *Manifest) { x.DatasetVersion = 99 },
		"records":         func(x *Manifest) { x.Payload.Records = 4 },
		"provenance":      func(x *Manifest) { x.Provenance[0].Records = 2 },
		"freshness":       func(x *Manifest) { x.Freshness.NewestObservedAt = time.Now().UTC().Add(time.Hour) },
		"notes":           func(x *Manifest) { x.Notes = "injected coverage claim" },
	} {
		x := *signed
		x.Provenance = append([]ProvenanceSummary(nil), signed.Provenance...)
		mutate(&x)
		if err := VerifyTrusted(&x); err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
			t.Fatalf("manifest tamper (%s) accepted: %v", name, err)
		}
	}
}

func TestWrongPublicKeyRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   4,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	raw, err := SignManifest(m, testPriv)
	if err != nil {
		t.Fatal(err)
	}
	// A verifier whose ring holds the SAME key ID but a DIFFERENT
	// public key (the "wrong key" case) must refuse the signature.
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	SetTestKeyring(Keyring{KeyID(testPub): otherPub})
	m2, err := ParseManifest(raw)
	if err != nil {
		t.Fatalf("signed manifest must parse under any ring: %v", err)
	}
	if err := VerifyTrusted(m2); err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
		t.Fatalf("manifest accepted against the WRONG public key: %v", err)
	}
	_ = otherPriv // only the public half belongs in the ring
	SetTestKeyring(Keyring{KeyID(testPub): testPub})
}

func TestUnknownKeyIDRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   5,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	if _, _, err := ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	raw, err := SignManifest(m, testPriv)
	if err != nil {
		t.Fatal(err)
	}
	signed := mustManifest(t, raw)
	// Forge a valid-looking signature block under an UNTRUSTED key ID
	// (the block's shape is fine — the key is simply not in the ring).
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = &ManifestSignature{
		Algorithm: SignatureAlgorithm,
		KeyID:     KeyID(otherPub),
		Value:     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	if err := VerifyTrusted(signed); err == nil || !strings.Contains(err.Error(), "E_DATASET_UNKNOWN_KEY") {
		t.Fatalf("unknown key ID accepted: %v", err)
	}
}

func TestMalformedSignatureBlockRejected(t *testing.T) {
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   6,
		GeneratedAtUTC:   time.Now().UTC(),
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
		Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
		Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
		ValidatorVersion: "1",
	}
	raw, err := SignManifest(m, testPriv)
	if err != nil {
		t.Fatal(err)
	}
	signed := mustManifest(t, raw)
	cases := map[string]struct {
		sig  *ManifestSignature
		want string // refusal code
	}{
		"bad algorithm": {&ManifestSignature{Algorithm: "rsa2048", KeyID: signed.Signature.KeyID, Value: signed.Signature.Value}, "E_DATASET_BAD_SIGNATURE"},
		"empty key id":  {&ManifestSignature{Algorithm: SignatureAlgorithm, KeyID: "", Value: signed.Signature.Value}, "E_DATASET_UNKNOWN_KEY"},
		"not base64":    {&ManifestSignature{Algorithm: SignatureAlgorithm, KeyID: signed.Signature.KeyID, Value: "!!!not base64!!!"}, "E_DATASET_BAD_SIGNATURE"},
		"wrong length":  {&ManifestSignature{Algorithm: SignatureAlgorithm, KeyID: signed.Signature.KeyID, Value: base64.StdEncoding.EncodeToString([]byte("short"))}, "E_DATASET_BAD_SIGNATURE"},
	}
	for name, tc := range cases {
		x := *signed
		x.Signature = tc.sig
		if err := x.Validate(); err == nil {
			t.Fatalf("malformed signature block (%s) accepted by Validate", name)
		}
		if err := VerifyTrusted(&x); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("malformed signature block (%s): want %s, got %v", name, tc.want, err)
		}
	}
}

// ---------------------------------------------------------------------------
// acceptance: rotation semantics
// ---------------------------------------------------------------------------

func TestKeyRotationSemantics(t *testing.T) {
	// Two-key ring (rotation in progress): a manifest signed by the NEW
	// key verifies while the OLD key remains listed.
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ring := Keyring{KeyID(oldPub): oldPub, KeyID(newPub): newPub}

	mk := func(version int64, priv ed25519.PrivateKey) *Manifest {
		m := &Manifest{
			SchemaVersion:    SchemaVersion,
			DatasetVersion:   version,
			GeneratedAtUTC:   time.Now().UTC(),
			Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 10, Records: 3},
			Rows:             RowsInfo{Assets: 1, Services: 0, Observations: 3},
			Provenance:       []ProvenanceSummary{{Source: "central-dns", Connector: "dns", Records: 3}},
			Freshness:        FreshnessInfo{OldestObservedAt: time.Now().UTC().Add(-time.Hour), NewestObservedAt: time.Now().UTC()},
			ValidatorVersion: "1",
		}
		raw, err := SignManifest(m, priv)
		if err != nil {
			t.Fatal(err)
		}
		return mustManifest(t, raw)
	}
	byOld, byNew := mk(10, oldPriv), mk(11, newPriv)
	if err := VerifyManifestSignature(byOld, ring); err != nil {
		t.Fatalf("old-key manifest refused during rotation: %v", err)
	}
	if err := VerifyManifestSignature(byNew, ring); err != nil {
		t.Fatalf("new-key manifest refused during rotation: %v", err)
	}
	// Rotation complete: the old key leaves the ring — old manifests are
	// refused with UNKNOWN KEY (fail-closed, never silently accepted).
	delete(ring, KeyID(oldPub))
	if err := VerifyManifestSignature(byOld, ring); err == nil || !strings.Contains(err.Error(), "E_DATASET_UNKNOWN_KEY") {
		t.Fatalf("retired key accepted: %v", err)
	}
	if err := VerifyManifestSignature(byNew, ring); err != nil {
		t.Fatalf("new-key manifest refused after rotation: %v", err)
	}
}

// TestParseManifestMalformedSignatureCoded — the parse-level SHAPE gate
// refuses a malformed signing block with the same E_DATASET_BAD_SIGNATURE
// code VerifyManifestSignature assigns to that class of defect (stable
// exit-code contract for consumers), never a bare un-coded message.
func TestParseManifestMalformedSignatureCoded(t *testing.T) {
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 21, []Record{
		domainRec("central-dns", time.Now().UTC().Add(-time.Minute), "example.com"),
	})
	for _, tc := range []struct {
		name string
		mut  func(s *ManifestSignature)
	}{
		{"malformed value", func(s *ManifestSignature) { s.Value = strings.Repeat("A", 128) }},
		{"missing key id", func(s *ManifestSignature) { s.KeyID = "" }},
		{"wrong algorithm", func(s *ManifestSignature) { s.Algorithm = "rsa" }},
	} {
		mutated := *m
		sig := *m.Signature
		tc.mut(&sig)
		mutated.Signature = &sig
		raw, err := json.MarshalIndent(&mutated, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseManifest(append(raw, '\n'))
		if err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
			t.Errorf("%s: must refuse with E_DATASET_BAD_SIGNATURE, got: %v", tc.name, err)
		}
	}
}
