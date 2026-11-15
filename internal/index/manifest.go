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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// manifest.go — the signed shared-index manifest (mirrors
// internal/update/manifest.go).
//
// The SIGNATURE covers the canonical JSON of the Manifest struct minus
// Signature (marshaled by encoding/json — field order is declaration
// order → deterministic).  The signed file is the Manifest with the
// signature set; verification re-marshals the core and checks the
// Ed25519 signature over those exact bytes.
//
// The manifest is the ATOMIC PUBLICATION POINTER: the provider pipeline
// replaces one small signed file (sequence + artifact coordinates); the
// snapshot artifact itself is immutable per sequence
// (gseer-index-<seq>.db), which makes rollback a re-point of the
// manifest to the previous sequence.
type Manifest struct {
	Format        string    `json:"format"` // always "gseer-index/1"
	Sequence      int64     `json:"sequence"`
	BuiltAt       time.Time `json:"built_at"`
	SchemaVersion int       `json:"schema_version"` // the snapshot's migration head
	ToolVersion   string    `json:"tool_version,omitempty"`
	Counts        Counts    `json:"counts"`
	Artifact      Artifact  `json:"artifact"`
	Signature     string    `json:"signature,omitempty"` // base64 Ed25519 over the canonical core
}

// Counts are the row totals the snapshot must contain (validated after
// download — the manifest is authoritative).
type Counts struct {
	Assets       int64 `json:"assets"`
	Services     int64 `json:"services"`
	Observations int64 `json:"observations"`
}

// Artifact describes the snapshot payload.
type Artifact struct {
	// URL is the absolute download URL of the snapshot file.  A
	// relative path is resolved against the manifest's URL directory.
	URL    string `json:"url"`
	SHA256 string `json:"sha256"` // hex
	Size   int64  `json:"size"`
}

// CanonicalCore renders the exact bytes the signature covers.
func (m Manifest) CanonicalCore() ([]byte, error) {
	m.Signature = ""
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Sign produces the signed manifest bytes from the core and a private
// key (the provider tool's operation; exported for tests and
// cmd/gseer-provider).
func Sign(m Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	core, err := m.CanonicalCore()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, core)
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return json.MarshalIndent(m, "", "  ")
}

// VerifySignature checks the manifest's Ed25519 signature over its
// canonical core.
func (m Manifest) VerifySignature(pub ed25519.PublicKey) error {
	if m.Signature == "" {
		return &Error{
			Code: CodeUnsigned,
			What: "the index manifest carries no signature",
			Why:  "an unsigned index is never applied — the download URL proves nothing",
			Next: "obtain a signed manifest from the official index channel (docs/SHARED-INDEX.md)",
		}
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return &Error{
			Code: CodeBadSignature,
			What: "the manifest signature is not a valid Ed25519 signature encoding",
			Why:  fmt.Sprintf("decode error: %v", err),
			Next: "refuse this manifest; fetch the official one",
		}
	}
	core, err := m.CanonicalCore()
	if err != nil {
		return &Error{Code: CodeMalformed, What: "manifest cannot be canonicalized", Why: err.Error()}
	}
	if !ed25519.Verify(pub, core, sig) {
		return &Error{
			Code: CodeBadSignature,
			What: "the manifest signature does not verify against the embedded public key",
			Why:  "the manifest was altered, forged, or signed by an unknown key",
			Next: "refuse this manifest; never apply an index that fails signature verification",
		}
	}
	return nil
}

// VerifyChecksum reports whether the recorded SHA-256 and size match
// the downloaded snapshot.
func (a Artifact) VerifyChecksum(payload []byte) error {
	sum := sha256.Sum256(payload)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, a.SHA256) {
		return &Error{
			Code: CodeChecksum,
			What: "the downloaded snapshot failed SHA-256 verification",
			Why:  fmt.Sprintf("got %s, manifest says %s", got[:16]+"…", a.SHA256[:16]+"…"),
			Next: "the snapshot was corrupted or tampered with; do not install it",
		}
	}
	if a.Size > 0 && int64(len(payload)) != a.Size {
		return &Error{
			Code: CodeChecksum,
			What: "the downloaded snapshot size does not match the manifest",
			Why:  fmt.Sprintf("got %d bytes, manifest says %d", len(payload), a.Size),
			Next: "refuse the snapshot; the manifest is authoritative",
		}
	}
	return nil
}

// ParseManifest decodes and structurally validates manifest bytes.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &Error{Code: CodeMalformed, What: "the index manifest is not valid JSON", Why: err.Error(),
			Next: "fetch the official manifest"}
	}
	if m.Format != FormatVersion {
		return nil, malformedf("manifest format %q is not %s — this build cannot read it", m.Format, FormatVersion)
	}
	if m.Sequence <= 0 {
		return nil, malformedf("manifest sequence %d is not positive", m.Sequence)
	}
	if m.BuiltAt.IsZero() {
		return nil, malformedf("manifest has no built_at timestamp")
	}
	if len(m.Artifact.SHA256) != 64 {
		return nil, malformedf("manifest artifact lacks a 64-hex sha256")
	}
	if m.Artifact.Size <= 0 {
		return nil, malformedf("manifest artifact size %d is not positive", m.Artifact.Size)
	}
	if m.Artifact.URL == "" {
		return nil, malformedf("manifest artifact has no URL")
	}
	if m.Counts.Assets < 0 || m.Counts.Services < 0 || m.Counts.Observations < 0 {
		return nil, malformedf("manifest counts are negative")
	}
	return &m, nil
}

// ResolveArtifactURL returns the artifact's absolute URL: the manifest
// value when already absolute, otherwise resolved against the manifest
// URL's directory (the release-assets layout: the manifest and the
// snapshot live side by side).
func (m Manifest) ResolveArtifactURL(manifestURL string) (string, error) {
	ref := strings.TrimSpace(m.Artifact.URL)
	if u, err := url.Parse(ref); err == nil && u.IsAbs() {
		return ref, nil
	}
	base, err := url.Parse(manifestURL)
	if err != nil {
		return "", &Error{Code: CodeURL, What: "the configured manifest URL is invalid", Why: err.Error()}
	}
	resolved := base.ResolveReference(&url.URL{Path: ref})
	return resolved.String(), nil
}
