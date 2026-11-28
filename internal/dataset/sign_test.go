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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package dataset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// signedTestManifest builds a structurally valid manifest and signs it
// with an ephemeral key (never the production anchor).
func signedTestManifest(t *testing.T) (*Manifest, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	m := &Manifest{
		SchemaVersion:    SchemaVersion,
		DatasetVersion:   42,
		GeneratedAtUTC:   now,
		Payload:          PayloadInfo{Filename: PayloadFilename, SHA256: strings.Repeat("ab", 32), SizeBytes: 100, Records: 3},
		Rows:             RowsInfo{Assets: 2, Services: 1, Observations: 3},
		Provenance:       []ProvenanceSummary{{Source: "test-src", Connector: "test", Records: 3, NewestObservedAt: now}},
		Freshness:        FreshnessInfo{OldestObservedAt: now, NewestObservedAt: now},
		ValidatorVersion: "1",
		Notes:            "synthetic test manifest",
	}
	doc, err := SignManifest(m, priv)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("ParseManifest(signed): %v", err)
	}
	if KeyID(pub) != m.Signature.KeyID {
		t.Fatalf("key id mismatch: %s != %s", KeyID(pub), m.Signature.KeyID)
	}
	return parsed, priv, doc
}

func useTestKeyring(t *testing.T, kr Keyring) {
	t.Helper()
	old := testKeyring
	SetTestKeyring(kr)
	t.Cleanup(func() { SetTestKeyring(old) })
}

func TestSignVerifyRoundtrip(t *testing.T) {
	m, _, doc := signedTestManifest(t)
	if m.Signature == nil || m.Signature.Value == "" {
		t.Fatal("signed manifest carries no signature block")
	}
	if !bytes.Contains(doc, []byte(`"signature"`)) {
		t.Fatal("signed document lost the signature object")
	}
	if m.Signature.Algorithm != SignatureAlgorithm {
		t.Fatalf("signature algorithm = %q, want %q", m.Signature.Algorithm, SignatureAlgorithm)
	}
}

func TestVerifySignedDocument(t *testing.T) {
	_, priv, doc := signedTestManifest(t)
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	useTestKeyring(t, Keyring{KeyID(pub): pub})
	if err := VerifyTrusted(doc, parsed); err != nil {
		t.Fatalf("VerifyTrusted(valid signed manifest) = %v, want nil", err)
	}
}

func TestUnsignedRefused(t *testing.T) {
	_, _, doc := signedTestManifest(t)
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed.Signature = nil
	useTestKeyring(t, nil)
	err = VerifyTrusted(doc, parsed)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_UNSIGNED") {
		t.Fatalf("unsigned manifest must be refused with E_DATASET_UNSIGNED, got: %v", err)
	}
}

func TestTamperedManifestRefused(t *testing.T) {
	_, priv, doc := signedTestManifest(t)
	tampered := bytes.Replace(doc, []byte(`"dataset_version": 42`), []byte(`"dataset_version": 43`), 1)
	if bytes.Equal(tampered, doc) {
		t.Fatal("tamper did not change the document")
	}
	pub := priv.Public().(ed25519.PublicKey)
	useTestKeyring(t, Keyring{KeyID(pub): pub})
	parsed, err := ParseManifest(tampered)
	if err != nil {
		t.Fatalf("tampered manifest still parses structurally: %v", err)
	}
	err = VerifyTrusted(tampered, parsed)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
		t.Fatalf("tampered manifest must be refused with E_DATASET_BAD_SIGNATURE, got: %v", err)
	}
}

func TestUnknownKeyRefused(t *testing.T) {
	_, _, doc := signedTestManifest(t)
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	foreignPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// The ring trusts only an unrelated key; the manifest's key id is unlisted.
	useTestKeyring(t, Keyring{KeyID(foreignPub): foreignPub})
	err = VerifyTrusted(doc, parsed)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_UNKNOWN_KEY") {
		t.Fatalf("unknown key must be refused with E_DATASET_UNKNOWN_KEY, got: %v", err)
	}
}

func TestWrongAlgorithmRefused(t *testing.T) {
	_, priv, doc := signedTestManifest(t)
	pub := priv.Public().(ed25519.PublicKey)
	useTestKeyring(t, Keyring{KeyID(pub): pub})
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed.Signature.Algorithm = "rsa"
	err = VerifyTrusted(doc, parsed)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
		t.Fatalf("foreign algorithm must be refused, got: %v", err)
	}
}

func TestBadSignatureEncodingRefused(t *testing.T) {
	_, priv, doc := signedTestManifest(t)
	pub := priv.Public().(ed25519.PublicKey)
	useTestKeyring(t, Keyring{KeyID(pub): pub})
	parsed, err := ParseManifest(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parsed.Signature.Value = "not-base64!!"
	err = VerifyTrusted(doc, parsed)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_BAD_SIGNATURE") {
		t.Fatalf("bad signature encoding must be refused, got: %v", err)
	}
}

func TestProductionAnchorPresent(t *testing.T) {
	SetTestKeyring(nil) // production ring
	kr := TrustKeyring()
	pub, ok := kr[EmbeddedDatasetKeyID]
	if !ok {
		t.Fatalf("production anchor %s missing from the keyring", EmbeddedDatasetKeyID)
	}
	if KeyID(pub) != EmbeddedDatasetKeyID {
		t.Fatalf("anchor key id derivation mismatch: %s", KeyID(pub))
	}
	if _, ok := kr[PriorChannelKeyID]; !ok {
		t.Fatalf("prior channel anchor %s missing during rotation window", PriorChannelKeyID)
	}
}

func TestCanonicalCoreDropsSignatureKeepsOrder(t *testing.T) {
	// signature placed FIRST must not change the core (document order,
	// signature excluded — proven against the live central channel).
	_, _, doc := signedTestManifest(t)
	core, err := canonicalCore(doc)
	if err != nil {
		t.Fatalf("canonicalCore: %v", err)
	}
	if bytes.Contains(core, []byte(`"signature"`)) {
		t.Fatal("canonical core still contains the signature object")
	}
	if bytes.Contains(core, []byte("\n")) || bytes.Contains(core, []byte("  ")) {
		t.Fatal("canonical core is not compact")
	}
	// reordered document: signature first, rest identical — the core must
	// contain the same fields in the same relative order (minus signature).
	var reordered bytes.Buffer
	reordered.WriteString(`{"signature":{"algorithm":"ed25519","key_id":"x","value":"y"},`)
	rest := core[1:] // strip leading '{'
	reordered.Write(rest)
	core2, err := canonicalCore(reordered.Bytes())
	if err != nil {
		t.Fatalf("canonicalCore(reordered): %v", err)
	}
	if !bytes.Equal(core, core2) {
		t.Fatal("canonical core must be independent of the signature position")
	}
}

// signForTest signs m with an ephemeral key and trusts that key for the
// duration of the test (cleanup restores the ring snapshot).  The ring
// ACCUMULATES: a test writing several manifests trusts them all.
func signForTest(t *testing.T, m *Manifest) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	doc, err := SignManifest(m, priv)
	if err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	old := testKeyring
	kr := Keyring{}
	for id, k := range TrustKeyring() {
		kr[id] = k
	}
	kr[KeyID(pub)] = pub
	SetTestKeyring(kr)
	t.Cleanup(func() { SetTestKeyring(old) })
	return doc
}
