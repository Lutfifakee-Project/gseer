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

package cli

// setup_index_test.go — the v0.3.2 Easy-to-Use acceptance (MASTER §14)
// against the REAL binary in a SUBPROCESS: fresh machine → setup →
// search, the client wizard, exit codes, the index lifecycle, and the
// scan-path fingerprint enrichment.
//
// Subprocess execution is deliberate: the CLI tree carries process-
// global state (cobra flag values, env overlays, the exitFunc seam),
// and the acceptance contract must hold for a REAL invocation — the
// same way scripts/v032-acceptance.sh runs it.  TestMain builds the
// binary once with -ldflags-injected TEST trust anchor (the same
// ldflags ceremony the production release uses), and every test drives
// the binary with a minimal environment and its own HOME.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/index"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// testGseerBin is the binary TestMain builds (with the test trust
// anchor injected via ldflags — the production ceremony's mechanism).
var testGseerBin string

// testChannelKey is the PRIVATE half matching the injected anchor.
var testChannelKey ed25519.PrivateKey

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gseer-cli-e2e-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "testmain temp:", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "testmain keygen:", err)
		os.Exit(1)
	}
	testChannelKey = priv

	ldflags := "-X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=" +
		base64.StdEncoding.EncodeToString(pub)
	binName := "gseer"
	if runtime.GOOS == "windows" {
		// Windows: build and run the conventional .exe name.  An
		// extension-less PE is fragile to execute via CreateProcess, and
		// a binary the tests cannot run fails the whole package in ways
		// the JSON log cannot attribute to a test.
		binName = "gseer.exe"
	}
	bin := filepath.Join(dir, binName)
	// The test runs with cwd = the package dir; build from the module
	// root (two levels up).
	modRoot, merr := filepath.Abs(filepath.Join("..", ".."))
	if merr != nil {
		fmt.Fprintln(os.Stderr, "testmain modroot:", merr)
		os.Exit(1)
	}
	goBin, lerr := exec.LookPath("go")
	if lerr != nil {
		// Report on BOTH streams: with `go test -json`, TestMain output
		// on stdout becomes JSON events visible in the job log, while
		// stderr lands only in the CI stderr file.  A TestMain that dies
		// before m.Run() produces NO per-test FAIL events (the Windows CI
		// evidence: internal/cli exit 1 with no failing test named), so
		// the diagnosis must be on stdout.
		fmt.Fprintf(os.Stdout, "testmain: go toolchain unavailable: %v\n", lerr)
		fmt.Fprintln(os.Stderr, "testmain: go toolchain unavailable:", lerr)
		os.Exit(1)
	}
	build := exec.Command(goBin, "build", "-ldflags", ldflags, "-o", bin, "./cmd/gseer")
	build.Dir = modRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stdout, "testmain go build failed: %v\n%s\n", err, out)
		fmt.Fprintf(os.Stderr, "testmain go build: %v\n%s", err, out)
		os.Exit(1)
	}
	testGseerBin = bin
	os.Exit(m.Run())
}

// subprocEnv builds a minimal, hermetic environment for the binary:
// no inherited GSEER_* state, HOME (and USERPROFILE on Windows)
// pointed at the test's fresh home, plus the OS-critical variables.
func subprocEnv(home string, extra map[string]string) []string {
	base := map[string]string{}
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		k, v := kv[:i], kv[i+1:]
		if strings.HasPrefix(k, "GSEER_") || k == "HOME" || k == "USERPROFILE" {
			continue
		}
		base[k] = v
	}
	base["HOME"] = home
	if runtime.GOOS == "windows" {
		base["USERPROFILE"] = home
	}
	for k, v := range extra {
		base[k] = v
	}
	env := make([]string, 0, len(base))
	for k, v := range base {
		env = append(env, k+"="+v)
	}
	return env
}

// runGseer runs the binary with the hermetic environment and returns
// (stdout+stderr, exit code).
func runGseer(t *testing.T, home string, extra map[string]string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(testGseerBin, args...) // #nosec G204 -- the test-built binary path
	cmd.Env = subprocEnv(home, extra)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %v: %v", args, err)
		}
	}
	return buf.String(), code
}

// indexChannel is a live signed index channel served by httptest: the
// pipeline store, the exported snapshot, and the signed manifest.
type indexChannel struct {
	srv         *httptest.Server
	sequence    int64
	manifestURL string
	artifact    []byte
}

// newIndexChannel seeds a pipeline store with REAL internet-asset
// rows (owner-domain style: DNS + Team-Cymru-shaped ASN enrichment),
// exports the snapshot, signs the manifest, and serves both files.
func newIndexChannel(t *testing.T, sequence int64) *indexChannel {
	t.Helper()
	ctx := context.Background()
	res, err := sqlite.Open(filepath.Join(t.TempDir(), "pipeline.db"))
	if err != nil {
		t.Fatalf("open pipeline store: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		t.Fatalf("migrate pipeline store: %v", err)
	}
	store := sqlite.NewStore(res.DB)
	srcID, err := store.EnsureSource(ctx, "e2e-dns", "dns", "operator-authorized DNS observation", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ip := "203.0.113.10"
	domain := "lutfifakee.top"
	assetID, _, err := store.UpsertAsset(ctx, &storage.Asset{
		Kind: storage.AssetKindIP, Value: ip, IP: &ip,
		ASN: 199695, ASNOrg: "ANYM-NET - PT Anym Network Indonesia", GeoCountry: "ID",
		Sources: []string{"dns", "ip2asn"}, FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, _, err := store.UpsertAsset(ctx, &storage.Asset{
		Kind: storage.AssetKindDomain, Value: domain, Domain: &domain,
		Sources: []string{"dns"}, FirstSeen: now, LastSeen: now,
	}); err != nil {
		t.Fatalf("asset2: %v", err)
	}
	if _, _, err := store.InsertObservation(ctx, &storage.Observation{
		ID: 1, SourceID: srcID, AssetID: assetID,
		ObservedAt: now, PayloadHash: "sha256:e2e-channel", SourceCursor: "v1|batch:e2e|rec:0",
		Provenance: "collect",
		Evidence:   map[string]any{"dns": map[string]any{"query": domain, "type": "A"}},
	}); err != nil {
		t.Fatalf("observation: %v", err)
	}

	snapPath := filepath.Join(t.TempDir(), "snapshot.db")
	counts, err := index.ExportSnapshot(ctx, store, snapPath)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	artifact, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	sum := sha256.Sum256(artifact)
	schema := 0
	if _, s, ierr := index.InspectSnapshot(ctx, snapPath); ierr == nil {
		schema = s
	}
	artifactName := fmt.Sprintf("gseer-index-%09d.db", sequence)
	m := index.Manifest{
		Format:        index.FormatVersion,
		Sequence:      sequence,
		BuiltAt:       time.Now().UTC(),
		SchemaVersion: schema,
		ToolVersion:   "cli-e2e",
		Counts:        *counts,
		Artifact:      index.Artifact{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(artifact))},
	}
	// The artifact URL is derived from the INCOMING request (r.Host) and
	// the manifest struct is copied per request: httptest.NewServer can
	// serve before the `srv :=` assignment completes, and two manifest
	// requests would otherwise race on the captured m (a write racing the
	// Sign read — the v0.3.2 acceptance data race). m itself stays
	// immutable, so no captured state is ever written.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gseer-index-manifest.json":
			mm := m
			u := *r.URL
			u.Scheme, u.Host = "http", r.Host
			u.Path, u.RawQuery, u.Fragment = "/"+artifactName, "", ""
			mm.Artifact.URL = u.String()
			signed, serr := index.Sign(mm, testChannelKey)
			if serr != nil {
				http.Error(w, serr.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(signed)
		case "/" + artifactName:
			_, _ = w.Write(artifact)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return &indexChannel{srv: srv, sequence: sequence, manifestURL: srv.URL + "/gseer-index-manifest.json", artifact: artifact}
}

// freshHome isolates the platform state for one test.
func freshHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	return home
}

func TestSubprocSetupFreshMachineSharedIndex(t *testing.T) {
	ch := newIndexChannel(t, 1)
	home := freshHome(t)

	out, code := runGseer(t, home, map[string]string{"GSEER_INDEX_MANIFEST_URL": ch.manifestURL}, "setup")
	if code != 0 {
		t.Fatalf("setup exited %d\noutput: %s", code, out)
	}
	for _, want := range []string{
		"Fresh install",
		"personal database",
		"shared index: verified + installed sequence 1",
		"imported:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup output missing %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".gseer", "config.yaml")); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".gseer", "index", "gseer-index.db")); err != nil {
		t.Fatalf("snapshot not installed: %v", err)
	}

	// MASTER §14: setup → search returns the REAL indexed asset.
	out, code = runGseer(t, home, nil, "search", "ip == \"203.0.113.10\"")
	if code != 0 || !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("search ip exited %d:\n%s", code, out)
	}
	// Bare keyword (unquoted) — the documented `gseer search 'nginx'` shape.
	out, code = runGseer(t, home, nil, "search", "lutfifakee")
	if code != 0 || !strings.Contains(out, "lutfifakee.top") {
		t.Fatalf("bare-keyword search exited %d:\n%s", code, out)
	}
	// Enrichment is searchable (ASN + org), including the new alias.
	out, code = runGseer(t, home, nil, "search", "asn == 199695", "--output", "json")
	if code != 0 || !strings.Contains(out, "ANYM-NET") {
		t.Fatalf("asn search exited %d:\n%s", code, out)
	}
	out, _ = runGseer(t, home, nil, "search", "ip_country == \"ID\"")
	if !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("ip_country alias search:\n%s", out)
	}
	// index status reflects the install.
	out, code = runGseer(t, home, nil, "index", "status")
	if code != 0 || !strings.Contains(out, "installed sequence: 1") || !strings.Contains(out, "imported into store: true") {
		t.Fatalf("index status exited %d:\n%s", code, out)
	}
	// doctor reports the shared index as PASS.
	out, _ = runGseer(t, home, nil, "doctor")
	if !strings.Contains(out, "shared index") || !strings.Contains(out, "PASS") {
		t.Fatalf("doctor shared-index check:\n%s", out)
	}
}

func TestSubprocSetupClientWizardPersistsEndpoint(t *testing.T) {
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/v1/health") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(health.Close)
	home := freshHome(t)

	out, code := runGseer(t, home, nil, "setup", "--server", health.URL)
	if code != 0 {
		t.Fatalf("wizard exited %d\noutput: %s", code, out)
	}
	if !strings.Contains(out, "config written") || !strings.Contains(out, "endpoint healthy") {
		t.Fatalf("wizard output:\n%s", out)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".gseer", "config.yaml"))
	if err != nil {
		t.Fatalf("config missing: %v", err)
	}
	if !strings.Contains(string(raw), "profile: client") || !strings.Contains(string(raw), health.URL) {
		t.Fatalf("endpoint not persisted:\n%s", raw)
	}
}

func TestSubprocSetupConfigFailureExits3(t *testing.T) {
	home := freshHome(t)
	out, code := runGseer(t, home, nil, "setup", "--profile", "client")
	if code != 3 {
		t.Fatalf("config failure exited %d, want 3 (ExitConfig)\noutput: %s", code, out)
	}
	if !strings.Contains(out, "E_CONFIG_REQUIRED") {
		t.Fatalf("config error not surfaced:\n%s", out)
	}
	// The hint must be actionable — the audited circular hint is gone.
	if !strings.Contains(out, "--server") {
		t.Fatalf("hint lacks the actionable --server command:\n%s", out)
	}
}

func TestSubprocIndexUpdateLifecycle(t *testing.T) {
	ch := newIndexChannel(t, 3)
	home := freshHome(t)
	extra := map[string]string{"GSEER_INDEX_MANIFEST_URL": ch.manifestURL}

	if out, code := runGseer(t, home, extra, "setup", "--personal"); code != 0 {
		t.Fatalf("personal setup exited %d\noutput: %s", code, out)
	}
	out, code := runGseer(t, home, extra, "index", "update", "--check")
	if code != 0 || !strings.Contains(out, "UPDATE AVAILABLE") || !strings.Contains(out, "remote sequence:  3") {
		t.Fatalf("check exited %d:\n%s", code, out)
	}
	out, code = runGseer(t, home, extra, "index", "update")
	if code != 0 || !strings.Contains(out, "manifest verified") || !strings.Contains(out, "imported:") {
		t.Fatalf("update exited %d:\n%s", code, out)
	}
	out, code = runGseer(t, home, nil, "search", "country == \"ID\"")
	if code != 0 || !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("imported row not searchable: exit %d\n%s", code, out)
	}
	out, _ = runGseer(t, home, extra, "index", "update")
	if !strings.Contains(out, "nothing to do") {
		t.Fatalf("second update output:\n%s", out)
	}
}

func TestSubprocIndexUpdateRefusesUnsignedManifestExit5(t *testing.T) {
	unsigned := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := index.Manifest{
			Format: index.FormatVersion, Sequence: 5, BuiltAt: time.Now().UTC(),
			Counts:   index.Counts{Assets: 1},
			Artifact: index.Artifact{URL: "a.db", SHA256: strings.Repeat("0", 64), Size: 1},
		}
		raw, _ := json.Marshal(m)
		_, _ = w.Write(raw)
	}))
	t.Cleanup(unsigned.Close)

	home := freshHome(t)
	extra := map[string]string{"GSEER_INDEX_MANIFEST_URL": unsigned.URL + "/gseer-index-manifest.json"}
	if out, code := runGseer(t, home, extra, "setup", "--personal"); code != 0 {
		t.Fatalf("personal setup exited %d\noutput: %s", code, out)
	}
	out, code := runGseer(t, home, extra, "index", "update")
	if code != 5 {
		t.Fatalf("unsigned manifest exited %d, want 5 (ExitAuth)\noutput: %s", code, out)
	}
	if !strings.Contains(out, "E_INDEX_UNSIGNED") {
		t.Fatalf("unsigned error not surfaced:\n%s", out)
	}
}

func TestSubprocScanEnrichesTechnologies(t *testing.T) {
	home := freshHome(t)
	if out, code := runGseer(t, home, nil, "setup", "--personal"); code != 0 {
		t.Fatalf("personal setup exited %d\noutput: %s", code, out)
	}
	// The operator-owned loopback target answers like nginx (a seed
	// rule matches http.server = nginx/<version>).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		fmt.Fprint(w, "<html><head><title>FP E2E</title></head></html>")
	}))
	t.Cleanup(srv.Close)
	port := srvPort(t, srv)

	out, code := runGseer(t, home, nil, "scope", "add", "cidr", "127.0.0.1/32",
		"--protocols", "http", "--ports", fmt.Sprintf("%d", port))
	if code != 0 || !strings.Contains(out, "Registered scope") {
		t.Fatalf("scope add exited %d:\n%s", code, out)
	}
	out, code = runGseer(t, home, nil, "scan", "http", "--target", "127.0.0.1", "--port", fmt.Sprintf("%d", port))
	if code != 0 || !strings.Contains(out, "status=200") {
		t.Fatalf("scan http exited %d:\n%s", code, out)
	}
	// STAGE 4 item 5: rule-derived technologies are searchable right
	// after the scan (scan-path engine wiring).
	out, code = runGseer(t, home, nil, "search", `technologies CONTAINS "nginx"`)
	if code != 0 || !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("technologies search exited %d:\n%s", code, out)
	}
}

func TestSubprocSecondSequenceKeepsPrevSnapshot(t *testing.T) {
	ch1 := newIndexChannel(t, 1)
	home := freshHome(t)
	extra := map[string]string{"GSEER_INDEX_MANIFEST_URL": ch1.manifestURL}
	if out, code := runGseer(t, home, extra, "setup"); code != 0 {
		t.Fatalf("setup exited %d\noutput: %s", code, out)
	}

	// A NEW sequence (fresh store rows → new artifact bytes).
	ch2 := newIndexChannel(t, 2)
	out, code := runGseer(t, home, map[string]string{"GSEER_INDEX_MANIFEST_URL": ch2.manifestURL}, "index", "update")
	if code != 0 || !strings.Contains(out, "installed atomically") {
		t.Fatalf("sequence-2 update exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".gseer", "index", "gseer-index.db.prev")); err != nil {
		t.Fatalf("previous snapshot not retained as .prev: %v", err)
	}
	out, _ = runGseer(t, home, nil, "index", "status")
	if !strings.Contains(out, "installed sequence: 2") {
		t.Fatalf("status after update:\n%s", out)
	}
}

func srvPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u := srv.URL
	i := strings.LastIndex(u, ":")
	if i < 0 {
		t.Fatalf("no port in %s", u)
	}
	var p int
	if _, err := fmt.Sscanf(u[i+1:], "%d", &p); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return p
}
