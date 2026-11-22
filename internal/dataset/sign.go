// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// sign.go — Ed25519 signing of the dataset manifest (P0-1: signed
// central dataset distribution).
//
// Binding (unambiguous): the signature covers the CANONICAL CORE of
// the manifest — the whole Manifest struct with Signature cleared,
// marshaled by encoding/json (field order is declaration order →
// deterministic).  The core therefore binds schema_version,
// dataset_version, generated_at_utc, the payload identity (filename,
// sha256, size_bytes, records), the row counts, the provenance
// summary, the freshness window, and the validator version.  Any
// manifest edit — including a single flipped bit of the payload hash —
// invalidates the signature; the payload itself is bound through
// payload.sha256 + size_bytes + records, which the fetcher re-derives
// from the downloaded bytes BEFORE the import path is ever reached.
//
// Trust: verification selects the trusted public key from the embedded
// keyring (keys.go) by the manifest's signature.key_id.  Missing
// signature, unknown key ID, malformed signature, or verification
// failure are all REFUSALS (E_DATASET_* errors) — the import path
// never sees an unverified manifest (fail-closed).
const SignatureAlgorithm = "ed25519"

// ManifestSignature is the manifest's signing block.
type ManifestSignature struct {
	// Algorithm is the signature scheme (only "ed25519" is accepted).
	Algorithm string `json:"algorithm"`
	// KeyID selects the trusted public key (the KeyID derivation).
	KeyID string `json:"key_id"`
	// Value is the base64 Ed25519 signature over the canonical core.
	Value string `json:"value"`
}

// validate enforces the signing block's shape (called from
// Manifest.Validate — the parse-level gate).  The failures carry the
// same E_DATASET_BAD_SIGNATURE code VerifyManifestSignature uses for
// the same class of defect, and the messages do NOT self-prefix
// "dataset:" — ParseManifest/FetchManifest add the package context, so
// a self-prefix would double it in consumer output.
func (s *ManifestSignature) validate() error {
	if s.Algorithm != SignatureAlgorithm {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: signature algorithm %q is not %q — refuse the manifest", s.Algorithm, SignatureAlgorithm)
	}
	if s.KeyID == "" {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: signature key_id is missing — refuse the manifest")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: signature value is not a valid Ed25519 signature encoding — refuse the manifest")
	}
	return nil
}

// CanonicalCore renders the exact bytes the signature covers: the
// manifest with the signature block cleared, marshaled compactly (the
// encoding/json field order is the struct declaration order, so the
// bytes are deterministic).
func (m *Manifest) CanonicalCore() ([]byte, error) {
	core := *m
	core.Signature = nil
	return json.Marshal(&core)
}

// SignManifest returns the signed manifest bytes: the canonical core is
// signed with priv, the signature block is filled in, and the result is
// the indented JSON document the channel publishes.  The publisher's
// operation (gseer-dataset sign); exported for the test suite.
func SignManifest(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	core, err := m.CanonicalCore()
	if err != nil {
		return nil, fmt.Errorf("dataset: manifest cannot be canonicalized: %w", err)
	}
	sig := ed25519.Sign(priv, core)
	m.Signature = &ManifestSignature{
		Algorithm: SignatureAlgorithm,
		KeyID:     KeyID(priv.Public().(ed25519.PublicKey)),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot encode the signed manifest: %w", err)
	}
	return append(b, '\n'), nil
}

// VerifyManifestSignature verifies m's signature against the given
// keyring.  Every failure is a refusal with an E_DATASET_* code — the
// Why/Try contract lives in the message text (the CLI prints it verbatim).
func VerifyManifestSignature(m *Manifest, kr Keyring) error {
	if m.Signature == nil {
		return fmt.Errorf("E_DATASET_UNSIGNED: the dataset manifest carries no signature — an unsigned dataset is never imported.\n" +
			"Why: the manifest checksum only proves self-consistency, not authorship.\n" +
			"Try: the publisher must sign it (docs/DATASET.md §5); refuse the channel until then")
	}
	s := m.Signature
	if s.Algorithm != SignatureAlgorithm {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: signature algorithm %q is not %q — refuse the manifest", s.Algorithm, SignatureAlgorithm)
	}
	pub, ok := kr[s.KeyID]
	if !ok {
		return fmt.Errorf("E_DATASET_UNKNOWN_KEY: manifest key_id %q is not a trusted dataset signing key (trusted: %s).\n"+
			"Why: verification never guesses — an unlisted key is untrusted.\n"+
			"Try: refuse the manifest; if the publisher rotated keys, upgrade gseer (docs/DATASET.md §6)", s.KeyID, keyringList(kr))
	}
	sig, err := base64.StdEncoding.DecodeString(s.Value)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: the manifest signature is not a valid Ed25519 signature encoding — refuse the manifest")
	}
	core, err := m.CanonicalCore()
	if err != nil {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: manifest cannot be canonicalized: %v", err)
	}
	if !ed25519.Verify(pub, core, sig) {
		return fmt.Errorf("E_DATASET_BAD_SIGNATURE: the manifest signature does not verify against key %s — the manifest was altered, forged, or signed by a foreign key.\n"+
			"Why: a valid signature is the only proof of authorship.\n"+
			"Try: refuse the manifest and fetch the official one; never import a manifest that fails signature verification", s.KeyID)
	}
	return nil
}

// VerifyTrusted verifies the manifest against the ACTIVE trust anchor
// (the embedded keyring; a test override in the test suite).  Every
// manifest that reaches the import path passes through here.
func VerifyTrusted(m *Manifest) error {
	return VerifyManifestSignature(m, TrustKeyring())
}

// ParseManifestUnsigned decodes a manifest WITHOUT the signature
// requirement (publisher-side pre-sign parsing in gseer-dataset).
// Consumer paths must use ParseManifest, which enforces the signature
// block at parse level (fail-closed).
func ParseManifestUnsigned(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("dataset: manifest does not parse: %w", err)
	}
	if err := m.ValidateCore(); err != nil {
		return nil, err
	}
	return &m, nil
}
