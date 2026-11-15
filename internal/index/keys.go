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

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// keys.go — the shared-index trust anchor (mirrors internal/update).
//
// EmbeddedIndexPublicKeyB64 is the base64 Ed25519 PUBLIC key that
// signed index manifests must verify against.  It is baked into the
// binary on purpose: an index manifest is only as trustworthy as this
// key, never as the URL it was fetched from.
//
// KEY CEREMONY (docs/SHARED-INDEX.md §2 — MANDATORY before publishing
// a production index): the project owner generates a dedicated Ed25519
// keypair with `gseer-provider keygen`, keeps the PRIVATE key offline /
// in the Actions secret store (INDEX_SIGNING_KEY), and ships the
// matching public half in release builds — either by replacing the
// default below or (preferred, no source edit) by building with
//
//	-ldflags "-X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=<prod-pub-b64>"
//
// The private key must NEVER live in this repository.  The bootstrap
// anchor below was generated for the v0.3.2 acceptance pipeline; treat
// it as a TEST anchor until the owner's ceremony replaces it.
// Rotation = new keypair + new embedded anchor + a signed revocation
// note in the release channel.
var EmbeddedIndexPublicKeyB64 = "NBdxzsWJq7WEAYXzR+s4KhnrDY3ZD7nnPemIl4viLCs="

// testKey overrides the embedded anchor in tests only (SetTestKey is
// wired through an internal seam so the embedded key stays the only
// production trust root).
var testKey ed25519.PublicKey

// SetTestPublicKey swaps the trust anchor (TESTS ONLY).
func SetTestPublicKey(pub ed25519.PublicKey) {
	testKey = pub
}

// TrustAnchor returns the active public key (test override wins).
func TrustAnchor() ed25519.PublicKey {
	if testKey != nil {
		return testKey
	}
	return embeddedKey()
}

func embeddedKey() ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(EmbeddedIndexPublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("index: embedded public key is invalid (decode err %v, len %d) — build broken", err, len(raw)))
	}
	return ed25519.PublicKey(raw)
}
