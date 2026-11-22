// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// keys.go — the dataset channel trust anchor (P0-1: signed central
// dataset distribution).
//
// EmbeddedDatasetPublicKeyB64 is the base64 Ed25519 PUBLIC key whose
// private half signs the central dataset manifests.  It is baked into
// the binary on purpose: a dataset manifest is only as trustworthy as
// this key, never as the URL it was fetched from.  The manifest is the
// authority ONLY because the publisher signs it — an unsigned or
// foreign-signed manifest is refused before anything is downloaded or
// imported.
//
// Embedding record (v0.3.2 release): the current key was minted with
// `gseer-dataset keygen` per §5 — the private seed was delivered to the
// owner OUTSIDE the source archive (0600) for one-time import into the
// CI secret store GSEER_DATASET_SIGNING_KEY.  It replaces the
// pre-release placeholder key 7b3879ab7a423772, which never signed a
// manifest (the live channel shipped unsigned from the pre-P0-1
// publisher) and never shipped in a released binary, so the §6
// keep-the-old-entry rotation rule does not apply to it.
//
// Key ceremony (docs/DATASET.md §5): the owner generates the keypair
// with `gseer-dataset keygen`, keeps the PRIVATE seed in the CI secret
// store (dataset.yml reads the GSEER_DATASET_SIGNING_KEY secret and
// hands it to `gseer-dataset sign` in memory; the seed NEVER enters the
// repository, the source tree, or any artifact), and embeds the public
// half + key ID here before cutting a release.  The delivered seed
// file travels OUTSIDE the source archive, 0600, to be imported into
// the CI secret store once.
//
// Rotation (docs/DATASET.md §6): generate a new keypair, ADD the new
// public key to the keyring below (keep the old entry — in-flight
// manifests keep verifying), publish with the new key, and remove the
// old entry after the following dataset version has shipped.  Recovery
// from a compromised key = rotate + re-publish immediately; a
// compromised key can only inject manifests until its entry is removed
// from this ring in a released binary.
const (
	// EmbeddedDatasetKeyID is the stable identifier of the embedded
	// production signing key: hex(sha256(pub)[:8]).  Manifests carry it
	// as signature.key_id so the verifier selects the right key without
	// guessing.
	EmbeddedDatasetKeyID = "5355d8197f5222d0"
	// EmbeddedDatasetPublicKeyB64 is the matching base64 Ed25519 public
	// key (ed25519.PublicKeySize = 32 raw bytes).
	EmbeddedDatasetPublicKeyB64 = "NCRlvXAZ2LnQgTXb+kfyn7V8y2a0tMWIbrYvwS6EpUs="
)

// Keyring maps key IDs to the public keys the CLI trusts for dataset
// manifest signatures.  Several IDs may coexist during a rotation; an
// unknown key ID is a hard refusal (fail-closed).
type Keyring map[string]ed25519.PublicKey

// testKeyring overrides the embedded anchor in tests only — the same
// seam contract as update.SetTestPublicKey: production paths always see
// the embedded keyring; the override exists so the signature/tamper
// suite can generate ephemeral keys instead of shipping a test key.
var testKeyring Keyring

// SetTestKeyring swaps the trust anchor (TESTS ONLY — not exported
// beyond the package seam the CLI wires for integration tests; the
// embedded keyring stays the only production trust root).
func SetTestKeyring(kr Keyring) { testKeyring = kr }

// TrustKeyring returns the active keyring (test override wins).
func TrustKeyring() Keyring {
	if testKeyring != nil {
		return testKeyring
	}
	return defaultKeyring()
}

// defaultKeyring builds the embedded production keyring.  A malformed
// embedded constant is a build error, not a runtime surprise: panic at
// first use with the exact reason.
func defaultKeyring() Keyring {
	raw, err := base64.StdEncoding.DecodeString(EmbeddedDatasetPublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("dataset: embedded public key is invalid (decode err %v, len %d) — build broken", err, len(raw)))
	}
	return Keyring{EmbeddedDatasetKeyID: ed25519.PublicKey(raw)}
}

// KeyID derives the stable key identifier: hex(sha256(pub)[:8]) — the
// same derivation `gseer-dataset keygen` prints and manifests carry.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func keyringList(kr Keyring) string {
	ids := make([]string, 0, len(kr))
	for id := range kr {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}
