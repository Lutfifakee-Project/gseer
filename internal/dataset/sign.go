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
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// sign.go — Ed25519 manifest signatures (P0-1: signed central dataset
// distribution).  The signature covers the manifest's CANONICAL CORE:
// the parsed document re-encoded as compact JSON in DOCUMENT ORDER with
// the signature object removed.  This design was proven against the
// live central channel (dataset v23, key 5355d8197f5222d0) before
// embedding: the verifier reproduces the publisher's signed bytes
// without depending on Go struct field order staying frozen.
//
// Publisher side (gseer-dataset sign): the core is signed, the
// signature block is filled in, and the indented document is published.
// Consumer side: every manifest that reaches the import path passes
// through VerifyTrusted — unsigned, foreign-signed, or altered
// manifests are refused with an E_DATASET_* code (fail-closed; the
// Why/Try contract lives in the message text, the CLI prints it
// verbatim).

// SignatureAlgorithm is the only accepted signature algorithm.
const SignatureAlgorithm = "ed25519"

// ManifestSignature is the signing block carried in the manifest.
type ManifestSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// canonicalCore re-encodes the parsed manifest document as compact JSON
// in document order, dropping the top-level "signature" object.  Raw
// values are compacted (the published document is indented) and keep
// the producer's exact number/string encodings.
func canonicalCore(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("manifest is not a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("manifest object key is not a string")
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, err
		}
		if key == "signature" {
			continue // the signature does not cover itself
		}
		var c bytes.Buffer
		if err := json.Compact(&c, val); err != nil {
			return nil, err
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		k, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		out.Write(k)
		out.WriteByte(':')
		out.Write(c.Bytes())
	}
	if _, err := dec.Token(); err != nil { // consume closing '}'
		return nil, err
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// SignManifest signs m's canonical core with priv and returns the
// indented manifest document the channel publishes (gseer-dataset sign).
func SignManifest(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	doc, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot encode the manifest: %w", err)
	}
	core, err := canonicalCore(doc)
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

// VerifyManifestSignature verifies the raw manifest document's
// signature against the given keyring.  Every failure is a refusal
// with an E_DATASET_* code.
func VerifyManifestSignature(raw []byte, m *Manifest, kr Keyring) error {
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
	core, err := canonicalCore(raw)
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

// VerifyTrusted verifies the raw manifest document against the ACTIVE
// trust anchor (the embedded keyring; a test override in the test
// suite).  Every manifest that reaches the import path passes through
// here — fetch.go calls it before the payload is downloaded, so an
// untrusted manifest never spends a payload request, let alone an
// import.
func VerifyTrusted(raw []byte, m *Manifest) error {
	return VerifyManifestSignature(raw, m, TrustKeyring())
}
