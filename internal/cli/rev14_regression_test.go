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

// rev14_regression_test.go — Rev14 blocker regression tests (owner
// verification finding: the seed-free discovery path was functional but
// the CLI help surfaces still described collection as seed-bound only,
// and the port=443 evidence path lacked an end-to-end regression).
//
// Pinned here:
//  1. command registration: `gseer source add --type ctlog --seed-mode
//     none` registers and lists (the owner's exact reproduction);
//  2. seed-free execution: a collect run against a local RFC 6962
//     log fixture ingests facts with NO seeds configured;
//  3. help surfaces: collect --help / source --help document the
//     seed-free path (a stale surface is a release blocker);
//  4. consumer import: a published dataset carrying ctlog + scan-tls
//     records imports, and `gseer search "port=443"` plus the CT
//     hostname search return the imported rows.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

// ── minimal RFC 6962 log fixture (mirrors internal/collect's tests) ────────

// rev14CertTBS extracts the TBSCertificate TLV from a full DER certificate.
func rev14CertTBS(t *testing.T, der []byte) []byte {
	t.Helper()
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("outer certificate: %v", err)
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &first); err != nil {
		t.Fatalf("first certificate element: %v", err)
	}
	return first.FullBytes
}

// rev14TestLeaf builds one RFC 6962 v1 MerkleTreeLeaf (TLS uint16
// entry_type — verified against a live log) around a real certificate.
func rev14TestLeaf(t *testing.T, entryType uint16, dnsNames []string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "rev14-regression"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if len(dnsNames) > 0 {
		tpl.DNSNames = dnsNames
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf := make([]byte, 0, 16+len(der))
	leaf = append(leaf, 0, 0) // version v1, timestamp signature
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	leaf = append(leaf, ts[:]...)
	leaf = append(leaf, byte(entryType>>8), byte(entryType))
	if entryType == 1 { // pre-cert: issuer_key_hash(32) || len3 || TBS
		leaf = append(leaf, make([]byte, 32)...)
		tbs := rev14CertTBS(t, der)
		leaf = append(leaf, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		leaf = append(leaf, tbs...)
		return leaf
	}
	leaf = append(leaf, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	leaf = append(leaf, der...)
	return leaf
}

// rev14ServeCTLog serves a fixed RFC 6962 log over httptest.
func rev14ServeCTLog(t *testing.T, leaves [][]byte) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": len(leaves), "timestamp": 1794926226023})
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		var start, end int
		_, _ = fmt.Sscanf(r.URL.Query().Get("start"), "%d", &start)
		_, _ = fmt.Sscanf(r.URL.Query().Get("end"), "%d", &end)
		type entry struct {
			LeafInput string `json:"leaf_input"`
		}
		entries := []entry{}
		for i := start; i <= end && i < len(leaves); i++ {
			if i < 0 {
				break
			}
			entries = append(entries, entry{LeafInput: base64.StdEncoding.EncodeToString(leaves[i])})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + "/"
}

// ── 1. command registration (the owner's exact reproduction) ───────────────

func TestSourceAddCTLogRegistersSeedFree(t *testing.T) {
	home := withDatasetEnv(t)
	resetSetupFlags(t)

	out, err := runCLI(t, "source", "add", "central-ctlog", "--type", "ctlog",
		"--seed-mode", "none", "--enable", "--yes")
	if err != nil {
		t.Fatalf("source add ctlog: %v\n%s", err, out)
	}
	if !strings.Contains(out, `Registered source "central-ctlog" (id=1, connector=ctlog, enabled=true)`) {
		t.Fatalf("registration output missing:\n%s", out)
	}
	if !strings.Contains(out, `"seed_mode":"none"`) {
		t.Fatalf("seed-mode none not persisted:\n%s", out)
	}

	list, err := runCLI(t, "source", "list")
	if err != nil {
		t.Fatalf("source list: %v\n%s", err, list)
	}
	if !strings.Contains(list, "central-ctlog") || !strings.Contains(list, "ctlog") {
		t.Fatalf("source list must show the ctlog source:\n%s", list)
	}
	_ = home
}

// ── 2. seed-free execution: facts land with NO seeds configured ────────────

// rev14ResetRunFlagChanges clears the pflag "Changed" marks on the collect
// run subcommand: the shared singleton command tree persists flag state
// across tests, and MarkFlagsMutuallyExclusive("source","all") would see a
// stale --all from an earlier test as still set.
func rev14ResetRunFlagChanges(t *testing.T) {
	t.Helper()
	cmd, _, err := RootCmd.Find([]string{"collect", "run"})
	if err != nil {
		t.Fatalf("find collect run: %v", err)
	}
	cmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false })
	t.Cleanup(func() { cmd.Flags().VisitAll(func(f *pflag.Flag) { f.Changed = false }) })
}

func TestSeedFreeCollectRunDiscoversWithoutSeeds(t *testing.T) {
	home := withDatasetEnv(t)
	resetSetupFlags(t)
	rev14ResetRunFlagChanges(t)

	leaves := make([][]byte, 30)
	for i := range leaves {
		leaves[i] = rev14TestLeaf(t, 0, []string{fmt.Sprintf("seedfree%d.example.net", i)})
	}
	leaves[29] = rev14TestLeaf(t, 1, []string{"precert-seedfree.example.net"})
	endpoint := rev14ServeCTLog(t, leaves)

	if _, err := runCLI(t, "setup", "--personal"); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}
	if _, err := runCLI(t, "source", "add", "central-ctlog", "--type", "ctlog",
		"--seed-mode", "none", "--endpoint", endpoint,
		"--requests-per-second", "50", "--enable", "--yes"); err != nil {
		t.Fatalf("source add: %v", err)
	}
	out, err := runCLI(t, "collect", "run", "--source", "central-ctlog")
	if err != nil {
		t.Fatalf("collect run: %v\n%s", err, out)
	}
	var stats struct {
		Source   string `json:"source"`
		Records  int    `json:"records"`
		Ingested int    `json:"ingested"`
	}
	dec := json.NewDecoder(strings.NewReader(out[strings.Index(out, "{"):]))
	if derr := dec.Decode(&stats); derr != nil {
		t.Fatalf("run stats not parseable from output:\n%s", out)
	}
	if stats.Source != "central-ctlog" || stats.Records <= 0 || stats.Ingested <= 0 {
		t.Fatalf("seed-free run must ingest facts (got %+v):\n%s", stats, out)
	}

	// The discovered names are searchable locally (search stays local).
	// NOTE: the search command's writer is set explicitly — earlier tests
	// in this package pin SetOut on the singleton search command, so the
	// runCLI root buffer no longer inherits for it.
	searchCmd, _, ferr := RootCmd.Find([]string{"search"})
	if ferr != nil {
		t.Fatalf("find search: %v", ferr)
	}
	searchOut := &bytes.Buffer{}
	searchCmd.SetOut(searchOut)
	t.Cleanup(func() { searchCmd.SetOut(nil) })
	if err := searchCmd.RunE(searchCmd, []string{`hostname CONTAINS "seedfree7.example.net"`}); err != nil {
		t.Fatalf("search: %v\n%s", err, searchOut.String())
	}
	if !strings.Contains(searchOut.String(), "seedfree7.example.net") {
		t.Fatalf("seed-free discovery must be searchable locally:\n%s", searchOut.String())
	}
	_ = home
}

// ── 3. help surfaces (the actual Rev14 blocker) ────────────────────────────

func TestCollectHelpDocumentsSeedFreeDiscovery(t *testing.T) {
	out, err := runCLI(t, "collect", "--help")
	if err != nil {
		t.Fatalf("collect --help: %v", err)
	}
	if strings.Contains(out, "targets only identifiers you configured") {
		t.Fatalf("STALE help text: collect --help must not claim seed-bound-only collection:\n%s", out)
	}
	if !strings.Contains(out, "SEED-FREE") || !strings.Contains(out, "ctlog") || !strings.Contains(out, "SOURCES.md §G") {
		t.Fatalf("collect --help must document the seed-free ctlog path (§G):\n%s", out)
	}
}

func TestSourceHelpListsCTLogVerdict(t *testing.T) {
	out, err := runCLI(t, "source", "--help")
	if err != nil {
		t.Fatalf("source --help: %v", err)
	}
	if !strings.Contains(out, "ctlog    reviewed-enabled") ||
		!strings.Contains(out, "SEED-FREE discovery: public CT logs, RFC 9162") ||
		!strings.Contains(out, "SOURCES.md §G") {
		t.Fatalf("source --help must list the ctlog verdict with its §G basis:\n%s", out)
	}
	if !strings.Contains(out, `"none" for the seed-free connectors`) {
		t.Fatalf("source --help must document seed-mode none:\n%s", out)
	}
}

// ── 4. consumer import: ctlog evidence + port=443 evidence, then search ────

func TestDatasetImportPort443AndCTLogEvidenceSearchable(t *testing.T) {
	home := withDatasetEnv(t)
	resetSetupFlags(t)

	now := time.Now().UTC().Add(-time.Minute)
	recs := []dataset.Record{
		{Schema: dataset.SchemaVersion,
			Asset: dataset.RecordAsset{Kind: "hostname", Value: "casinospel365.se", Hostname: strPtr("casinospel365.se")},
			Observation: dataset.RecordObservation{
				Source: "central-ctlog", Connector: "ctlog", ObservedAt: now,
				PayloadHash: "sha256:rev14-ct-regression", Provenance: "ctlog",
				Evidence: map[string]any{"ctlog": map[string]any{
					"log":         "https://ct.cloudflare.com/logs/nimbus2026/",
					"index":       6799328683,
					"leaf_sha256": "a" + strings.Repeat("b", 63),
					"entry_type":  "x509",
				}},
			}},
		{Schema: dataset.SchemaVersion,
			Asset:   dataset.RecordAsset{Kind: "ip", Value: "93.184.216.34", IP: strPtr("93.184.216.34")},
			Service: &dataset.RecordService{Port: 443, Transport: "tcp", Protocol: "https"},
			Observation: dataset.RecordObservation{
				Source: "central-scan", Connector: "scan-tls", ObservedAt: now,
				PayloadHash: "sha256:rev14-tls-443", Provenance: "scan-tls",
				Evidence: map[string]any{"tls_version": "TLS 1.3"},
			}},
	}
	channel := serveTestDataset(t, 43, recs)

	updateCmd, _, err := RootCmd.Find([]string{"dataset", "update"})
	if err != nil {
		t.Fatal(err)
	}
	upd := &bytes.Buffer{}
	updateCmd.SetOut(upd)
	if err := updateCmd.Flags().Set("manifest-url", channel); err != nil {
		t.Fatal(err)
	}
	if err := updateCmd.RunE(updateCmd, nil); err != nil {
		t.Fatalf("dataset update: %v\n%s", err, upd.String())
	}

	// port=443: the imported SERVICE evidence must answer the owner's query.
	searchCmd, _, err := RootCmd.Find([]string{"search"})
	if err != nil {
		t.Fatal(err)
	}
	pOut := &bytes.Buffer{}
	searchCmd.SetOut(pOut)
	if err := searchCmd.RunE(searchCmd, []string{"port=443"}); err != nil {
		t.Fatalf("search port=443: %v\n%s", err, pOut.String())
	}
	if !strings.Contains(pOut.String(), "93.184.216.34") || !strings.Contains(pOut.String(), ":443") {
		t.Fatalf(`search "port=443" must return the imported TLS row:\n%s`, pOut.String())
	}

	// The CT-discovered hostname must answer its query too.
	hOut := &bytes.Buffer{}
	searchCmd.SetOut(hOut)
	if err := searchCmd.RunE(searchCmd, []string{`hostname CONTAINS "casinospel365.se"`}); err != nil {
		t.Fatalf("search hostname: %v\n%s", err, hOut.String())
	}
	if !strings.Contains(hOut.String(), "casinospel365.se") {
		t.Fatalf("imported ctlog asset must be searchable locally:\n%s", hOut.String())
	}
	_ = home
}

// silence unused-context lint in the fixture helpers
var _ = context.Background
