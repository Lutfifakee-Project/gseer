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

// gseer-provider — the maintainer-side companion of the v0.3.2 shared
// index (docs/SHARED-INDEX.md; the scheduled GitHub Actions pipeline is
// the primary operator of this tool):
//
//	gseer-provider keygen -pub PUB -priv PRIV
//	    generate the Ed25519 INDEX signing keypair (a dedicated key,
//	    separate from the binary-update key of cmd/gseer-release).
//	gseer-provider build -store PIPELINE.db -out SNAPSHOT.db
//	    export the collected index into an immutable snapshot file.
//	gseer-provider manifest -snapshot SNAP.db -sequence N
//	                   -artifact-url URL -key PRIV -out MANIFEST.json
//	    build + sign the manifest (Ed25519 over the canonical core).
//	gseer-provider verify -manifest MANIFEST.json [-artifact SNAP.db]
//	    pre-publication self-check (the same verification the client
//	    runs: signature → checksum).
//
// This tool ships in the repository but is NOT part of the `gseer`
// binary: end-user machines never need signing capability.  The
// PRIVATE key lives only in the pipeline's secret store
// (INDEX_SIGNING_KEY); the PUBLIC half is embedded in
// internal/index/keys.go.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/index"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gseer-provider: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		keygen(os.Args[2:])
	case "build":
		buildCmd(os.Args[2:])
	case "manifest":
		manifestCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	case "inspect":
		inspectCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gseer-provider — shared-index provider tooling (docs/SHARED-INDEX.md)

  gseer-provider keygen  -pub PUB -priv PRIV
  gseer-provider build   -store PIPELINE.db -out SNAPSHOT.db
  gseer-provider manifest -snapshot SNAP.db -sequence N
                          -artifact-url URL -key PRIV -out MANIFEST.json
  gseer-provider verify  -manifest MANIFEST.json [-artifact SNAP.db]
  gseer-provider inspect -snapshot SNAP.db [-manifest MANIFEST.json]
`)
	os.Exit(2)
}

func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pubPath := fs.String("pub", "gseer-index.pub", "public key output (base64)")
	privPath := fs.String("priv", "gseer-index.key", "private key output (base64; KEEP OFFLINE)")
	_ = fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("keygen: %v", err)
	}
	// #nosec G306 -- the PUBLIC key is a public artifact; the private half is written 0600 below.
	if err := os.WriteFile(*pubPath, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		fatal("write pub: %v", err)
	}
	if err := os.WriteFile(*privPath, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		fatal("write priv: %v", err)
	}
	fmt.Printf("public  key → %s (embed this base64 in internal/index/keys.go)\n", *pubPath)
	fmt.Printf("private key → %s (mode 0600; keep offline; NEVER commit)\n", *privPath)
}

func loadPriv(path string) ed25519.PrivateKey {
	raw, err := os.ReadFile(path) // #nosec G304,G703 -- the key ceremony tool reads the operator-supplied private-key path (the taint IS the tool's purpose: -key is the operator's own flag)
	if err != nil {
		fatal("read key: %v", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(trimSpaceBytes(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		fatal("%s is not a base64 Ed25519 private key (len %d)", path, len(key))
	}
	return ed25519.PrivateKey(key)
}

func trimSpaceBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

func buildCmd(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	storePath := fs.String("store", "", "the pipeline store (personal-mode SQLite) to export")
	out := fs.String("out", "gseer-index-snapshot.db", "snapshot output path")
	_ = fs.Parse(args)
	if *storePath == "" {
		fatal("build: -store is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	src, closeSrc, err := openStoreForExport(*storePath)
	if err != nil {
		fatal("build: %v", err)
	}
	defer closeSrc()

	counts, err := index.ExportSnapshot(ctx, src, *out)
	if err != nil {
		fatal("build: %v", err)
	}
	payload, err := os.ReadFile(*out) // #nosec G304 -- the tool reads the snapshot it just produced
	if err != nil {
		fatal("build: read snapshot: %v", err)
	}
	sum := sha256.Sum256(payload)
	fmt.Printf("snapshot    → %s\n", *out)
	fmt.Printf("counts      → assets %d, services %d, observations %d\n", counts.Assets, counts.Services, counts.Observations)
	fmt.Printf("sha256      → %s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("size        → %d bytes\n", len(payload))
	fmt.Printf("next        → gseer-provider manifest -snapshot %s -sequence <N+1> -artifact-url <URL> -key PRIV -out manifest.json\n", *out)
}

func manifestCmd(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	snapPath := fs.String("snapshot", "", "the built snapshot file")
	sequence := fs.Int64("sequence", 0, "the monotonic sequence number (previous manifest sequence + 1)")
	artifactURL := fs.String("artifact-url", "", "the absolute URL the snapshot will be published at")
	toolVersion := fs.String("tool-version", "", "the producing tool version (informational)")
	keyPath := fs.String("key", "", "the Ed25519 PRIVATE key (base64 file; or GSEER_INDEX_SIGNING_KEY env)")
	out := fs.String("out", "gseer-index-manifest.json", "signed manifest output")
	_ = fs.Parse(args)
	if *snapPath == "" || *sequence <= 0 || *artifactURL == "" || *out == "" {
		fatal("manifest: -snapshot, -sequence (>0), -artifact-url and -out are required")
	}
	keyFile := *keyPath
	if keyFile == "" {
		keyFile = os.Getenv("GSEER_INDEX_SIGNING_KEY")
	}
	if keyFile == "" {
		fatal("manifest: no signing key — pass -key or set GSEER_INDEX_SIGNING_KEY")
	}
	priv := loadPriv(keyFile)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	counts, schema, err := index.InspectSnapshot(ctx, *snapPath)
	if err != nil {
		fatal("manifest: %v", err)
	}
	payload, err := os.ReadFile(*snapPath) // #nosec G304 -- the tool hashes the snapshot it is about to publish
	if err != nil {
		fatal("manifest: read snapshot: %v", err)
	}
	sum := sha256.Sum256(payload)
	m := index.Manifest{
		Format:        index.FormatVersion,
		Sequence:      *sequence,
		BuiltAt:       time.Now().UTC(),
		SchemaVersion: schema,
		ToolVersion:   *toolVersion,
		Counts:        *counts,
		Artifact: index.Artifact{
			URL:    *artifactURL,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(payload)),
		},
	}
	signed, err := index.Sign(m, priv)
	if err != nil {
		fatal("manifest: sign: %v", err)
	}
	if err := os.WriteFile(*out, signed, 0o600); err != nil { // #nosec G306,G703 -- the manifest carries no secrets (only hashes/URLs); 0600 keeps the local artifact least-privilege; -out is the operator's own flag
		fatal("manifest: write: %v", err)
	}
	fmt.Printf("manifest    → %s (sequence %d, schema v%d)\n", *out, m.Sequence, schema)
	fmt.Printf("artifact    → %s (sha256 %s…, %d bytes)\n", *artifactURL, m.Artifact.SHA256[:16], m.Artifact.Size)
	fmt.Printf("counts      → assets %d, services %d, observations %d\n", counts.Assets, counts.Services, counts.Observations)
	fmt.Printf("next        → publish BOTH files to the durable channel (immutable snapshot + pointer manifest), then verify the public URL\n")
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "the signed manifest to verify")
	artifactPath := fs.String("artifact", "", "optional: the snapshot file to checksum-verify against the manifest")
	_ = fs.Parse(args)
	if *manifestPath == "" {
		fatal("verify: -manifest is required")
	}
	raw, err := os.ReadFile(*manifestPath) // #nosec G304 -- the tool reads the operator-supplied manifest path
	if err != nil {
		fatal("verify: read manifest: %v", err)
	}
	m, err := index.ParseManifest(raw)
	if err != nil {
		fatal("verify: %v", err)
	}
	if err := m.VerifySignature(index.TrustAnchor()); err != nil {
		fatal("verify: %v", err)
	}
	fmt.Printf("signature   → VALID (sequence %d, built %s, schema v%d)\n", m.Sequence, m.BuiltAt.Format(time.RFC3339), m.SchemaVersion)
	if *artifactPath != "" {
		payload, err := os.ReadFile(*artifactPath) // #nosec G304 -- the tool hashes the operator-supplied artifact path
		if err != nil {
			fatal("verify: read artifact: %v", err)
		}
		if err := m.Artifact.VerifyChecksum(payload); err != nil {
			fatal("verify: %v", err)
		}
		fmt.Printf("checksum    → VALID (%d bytes)\n", len(payload))
	}
}

// inspectCmd is the restore-time snapshot gate of the cumulative
// pipeline (docs/SHARED-INDEX.md §3): SQLite integrity_check + schema
// position (never NEWER than this build — an older provider must not
// restore a schema-ahead base), with an optional consistency
// cross-check against the signed manifest (sequence >= 1, schema and
// counts must match).  Signature and checksum verification remain the
// `verify` command's job; this command proves the verified artifact IS
// a healthy GSEER snapshot before it becomes the working store.
func inspectCmd(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	snapPath := fs.String("snapshot", "", "the snapshot file to inspect")
	manifestPath := fs.String("manifest", "", "optional: the signed manifest to cross-check against")
	_ = fs.Parse(args)
	if *snapPath == "" {
		fatal("inspect: -snapshot is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	counts, schema, err := index.InspectSnapshot(ctx, *snapPath)
	if err != nil {
		fatal("inspect: %v", err)
	}
	fmt.Printf("integrity   → OK (SQLite integrity_check)\n")
	fmt.Printf("schema      → v%d (not NEWER than this build)\n", schema)
	fmt.Printf("counts      → assets %d, services %d, observations %d\n", counts.Assets, counts.Services, counts.Observations)

	if *manifestPath != "" {
		raw, err := os.ReadFile(*manifestPath) // #nosec G304 -- the tool reads the operator-supplied manifest path
		if err != nil {
			fatal("inspect: read manifest: %v", err)
		}
		m, err := index.ParseManifest(raw)
		if err != nil {
			fatal("inspect: %v", err)
		}
		if m.Sequence <= 0 {
			fatal("inspect: the manifest's sequence must be >= 1 (got %d) — refuse the restore", m.Sequence)
		}
		if m.SchemaVersion != schema {
			fatal("inspect: manifest schema (v%d) != snapshot schema (v%d) — refuse the restore", m.SchemaVersion, schema)
		}
		if m.Counts != *counts {
			fatal("inspect: manifest counts do not match the snapshot (assets %d/%d, services %d/%d, observations %d/%d) — refuse the restore",
				counts.Assets, m.Counts.Assets, counts.Services, m.Counts.Services, counts.Observations, m.Counts.Observations)
		}
		fmt.Printf("manifest    → CONSISTENT (sequence %d, schema v%d, counts match)\n", m.Sequence, m.SchemaVersion)
	}
}

// openStoreForExport opens the pipeline store for the export (read
// side only — the snapshot is a fresh file).
func openStoreForExport(path string) (*sqlite.Store, func(), error) {
	res, err := sqlite.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		_ = res.DB.Close()
		return nil, nil, err
	}
	return sqlite.NewStore(res.DB), func() { _ = res.DB.Close() }, nil
}
