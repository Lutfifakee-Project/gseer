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

package collect

// ctlog_test.go — the seed-free CT log connector's contract tests.  The
// httptest server speaks the RFC 6962 JSON protocol (get-sth/get-entries)
// with REAL DER certificates built in-process — no network, no provider.

import (
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
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ctlogTBS extracts the TBSCertificate TLV bytes from a full certificate
// DER (Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
// signatureValue } — the pre-cert entry carries the bare TBS).
func ctlogTBS(t *testing.T, der []byte) []byte {
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

// ctlogTestLeaf builds one RFC 6962 v1 MerkleTreeLeaf around a real
// self-signed certificate.  entryType 0 = x509_entry (3-byte length ||
// DER); entryType 1 = pre-cert_entry (issuer_key_hash(32) || 3-byte
// length || TBSCertificate) — the TBS is extracted from the same DER.
func ctlogTestLeaf(t *testing.T, entryType uint16, dnsNames []string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ctlog-test"},
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
	leaf := make([]byte, 0, 14+len(der))
	leaf = append(leaf, ctlogLeafVersionV1, 0) // version v1, timestamp signature
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixMilli()))
	leaf = append(leaf, ts[:]...)
	// entry_type: TLS uint16 discriminator (verified against a live log)
	leaf = append(leaf, byte(entryType>>8), byte(entryType))
	if entryType == ctlogEntryPrecert {
		leaf = append(leaf, make([]byte, 32)...) // issuer_key_hash (unused by the parser)
		tbs := ctlogTBS(t, der)
		leaf = append(leaf, byte(len(tbs)>>16), byte(len(tbs)>>8), byte(len(tbs)))
		leaf = append(leaf, tbs...)
		return leaf
	}
	leaf = append(leaf, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	leaf = append(leaf, der...)
	return leaf
}

// ctlogTestLog serves a fixed RFC 6962 log over httptest: treeSize entries
// numbered 0..treeSize-1, served from the given leaves in order.  It
// records the (start,end) pairs it was asked for.
func ctlogTestLog(t *testing.T, treeSize int, leaves [][]byte) (string, *[]string) {
	t.Helper()
	var asks []string
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tree_size": treeSize, "timestamp": 1794926226023})
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		asks = append(asks, r.URL.RawQuery)
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
	return ts.URL + "/", &asks
}

func ctlogTestCtx(t *testing.T, endpoint string, mutate func(*Ctx)) Ctx {
	t.Helper()
	c := Ctx{
		Context: context.Background(),
		Client:  NewClient(ClientConfig{RequestsPerSecond: 10_000, Timeout: 2 * time.Second}),
		Config:  SourceConfig{Endpoint: endpoint, SeedMode: "none"},
		Now:     func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) },
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

// TestCTLogTipFollow — the default (no cursor, no start_index) reads the
// FRESHEST window: start = tree_size - budget, budget entries max, and
// the discovered names carry the log/index/leaf-hash provenance.
func TestCTLogTipFollow(t *testing.T) {
	// Ten-entry log; the tip window 6..9 holds two x509 certs, one
	// pre-certificate and one v2 (RFC 9162) leaf.
	leaves := [][]byte{
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s0.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s1.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s2.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s3.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s4.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"s5.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"c.example.com"}),
		ctlogTestLeaf(t, ctlogEntryX509, []string{"d.example.com"}),
		ctlogTestLeaf(t, ctlogEntryPrecert, []string{"precert.example.com"}),
		{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // version 2: skipped
	}
	endpoint, asks := ctlogTestLog(t, 10, leaves)
	col := ctlogConnector{}
	batch, err := col.Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) { c.Limit = 4 }))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got := batch.Notes["entries"]; got != 4 {
		t.Fatalf("entries = %d, want 4 (window 6..9)", got)
	}
	var names []string
	for _, r := range batch.Raws {
		if r.AssetKind != "hostname" || r.Confidence != "high" {
			t.Fatalf("raw fact kind/confidence: %+v", r)
		}
		names = append(names, strings.ToLower(r.Value))
		ct, ok := r.Extra["ctlog"].(map[string]any)
		if !ok || ct["log"] == "" || ct["leaf_sha256"] == "" || ct["index"] == nil {
			t.Fatalf("missing ctlog provenance in %+v", r.Extra)
		}
	}
	if len(names) != 3 || names[0] != "c.example.com" || names[1] != "d.example.com" || names[2] != "precert.example.com" {
		t.Fatalf("names = %v, want [c.example.com d.example.com precert.example.com]", names)
	}
	if batch.Notes["precerts"] != 1 || batch.Notes["certs"] != 2 || batch.Notes["non_leaf"] != 1 || batch.Notes["leaf_errors"] != 0 {
		t.Fatalf("skip accounting: %+v, want precerts=1 certs=2 non_leaf=1 leaf_errors=0", batch.Notes)
	}
	if !batch.Done {
		t.Fatal("Done = false, want true (one bounded batch per run)")
	}
	if batch.Cursor != "9" {
		t.Fatalf("Cursor = %q, want 9 (last consumed index)", batch.Cursor)
	}
	if len(*asks) == 0 || !strings.Contains((*asks)[0], "start=6") {
		t.Fatalf("first ask = %v, want start=6 (tip = 10-4)", *asks)
	}
}

// TestCTLogResumeFromCursor — the checkpoint stores the LAST consumed
// index; the next run resumes at cursor+1 and never re-reads it.
func TestCTLogResumeFromCursor(t *testing.T) {
	leaves := make([][]byte, 8)
	for i := range leaves {
		leaves[i] = ctlogTestLeaf(t, ctlogEntryX509, []string{fmt.Sprintf("h%d.example.com", i)})
	}
	endpoint, asks := ctlogTestLog(t, 8, leaves)
	col := ctlogConnector{}
	batch, err := col.Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) {
		c.Limit = 3
		c.Cursor = "4" // consumed 0..4 → resume at 5
	}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains((*asks)[0], "start=5") {
		t.Fatalf("first ask = %v, want start=5 (cursor 4 → +1)", *asks)
	}
	if batch.Notes["entries"] != 3 || batch.Cursor != "7" {
		t.Fatalf("entries/cursor = %v/%q, want 3/7", batch.Notes["entries"], batch.Cursor)
	}
}

// TestCTLogBudgetBounded — one run never exceeds its entry budget, and
// chunk requests are capped by the RFC 6962 get-entries answer limit.
func TestCTLogBudgetBounded(t *testing.T) {
	leaves := make([][]byte, 2000)
	for i := range leaves {
		leaves[i] = ctlogTestLeaf(t, ctlogEntryX509, []string{fmt.Sprintf("x%d.example.com", i)})
	}
	endpoint, asks := ctlogTestLog(t, 2000, leaves)
	col := ctlogConnector{}
	batch, err := col.Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) {
		c.Limit = 1001 // forces chunk cap (1000) + a second request of 1
		c.Config.Chunk = 5000
	}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if batch.Notes["entries"] != 1001 {
		t.Fatalf("entries = %d, want 1001 (budget enforced)", batch.Notes["entries"])
	}
	if len(*asks) != 2 {
		t.Fatalf("requests = %d, want 2 (chunk capped at 1000)", len(*asks))
	}
	if batch.Cursor != "1999" {
		t.Fatalf("Cursor = %q, want 1999", batch.Cursor)
	}
}

// TestCTLogPrecertNamesAndV2Skipped — pre-certificate TBS SANs are PARSED
// (the freshest window of a public log is precert-dominated — the live
// E2E proved skipping them yields zero names), and RFC 9162 v2 leaves are
// skipped honestly.
func TestCTLogPrecertNamesAndV2Skipped(t *testing.T) {
	leaves := [][]byte{
		ctlogTestLeaf(t, ctlogEntryPrecert, []string{"precert.example.com", "*.wild.example.com"}),
		{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // version 2 leaf (12 bytes — version skip, not an error)
	}
	endpoint, _ := ctlogTestLog(t, 2, leaves)
	batch, err := ctlogConnector{}.Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) { c.Limit = 10 }))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(batch.Raws) != 2 {
		t.Fatalf("raws = %d, want 2 (precert SAN + wildcard base)", len(batch.Raws))
	}
	got := []string{strings.ToLower(batch.Raws[0].Value), strings.ToLower(batch.Raws[1].Value)}
	if got[0] != "precert.example.com" || got[1] != "wild.example.com" {
		t.Fatalf("names = %v, want [precert.example.com wild.example.com]", got)
	}
	if batch.Notes["precerts"] != 1 || batch.Notes["certs"] != 0 || batch.Notes["non_leaf"] != 1 || batch.Notes["leaf_errors"] != 0 {
		t.Fatalf("notes = %+v, want precerts=1 certs=0 non_leaf=1 leaf_errors=0", batch.Notes)
	}
	et := batch.Raws[0].Extra["ctlog"].(map[string]any)["entry_type"]
	if et != "precert" {
		t.Fatalf("entry_type = %v, want precert", et)
	}
}

// TestCTLogNamesWildcardDedupe — wildcards collapse to their base name,
// case variants dedupe within the batch, and the apex arrives as a
// hostname sighting (no PLS guessing: kind stays what the source states).
func TestCTLogNamesWildcardDedupe(t *testing.T) {
	leaves := [][]byte{ctlogTestLeaf(t, ctlogEntryX509, []string{"*.Foo.com", "WWW.foo.com", "foo.com"})}
	endpoint, _ := ctlogTestLog(t, 1, leaves)
	batch, err := ctlogConnector{}.Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) { c.Limit = 10 }))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	var names []string
	for _, r := range batch.Raws {
		names = append(names, r.Value)
	}
	if len(names) != 2 || strings.ToLower(names[0]) != "foo.com" || strings.ToLower(names[1]) != "www.foo.com" {
		t.Fatalf("names = %v, want [foo.com www.foo.com] (wildcard base + host, apex deduped)", names)
	}
}

// TestCTLogGuards — nil client and a seed mode are hard, honest fatals.
func TestCTLogGuards(t *testing.T) {
	endpoint, _ := ctlogTestLog(t, 1, [][]byte{ctlogTestLeaf(t, ctlogEntryX509, []string{"a.com"})})
	if _, err := (ctlogConnector{}).Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) { c.Client = nil })); err == nil || !strings.Contains(err.Error(), "no HTTP client") {
		t.Fatalf("nil client: err = %v, want no-HTTP-client fatal", err)
	}
	if _, err := (ctlogConnector{}).Collect(ctlogTestCtx(t, endpoint, func(c *Ctx) { c.Config.SeedMode = "config" })); err == nil || !strings.Contains(err.Error(), "seed-free") {
		t.Fatalf("seed-mode config: err = %v, want seed-free fatal", err)
	}
}

// TestCTLogReviewEnabled — the terms gate must see this connector as
// review-enabled with the §G doc reference (Runner.Run refuses otherwise).
func TestCTLogReviewEnabled(t *testing.T) {
	rv := ctlogConnector{}.Review()
	if rv.Verdict != ReviewEnabled || !strings.Contains(rv.DocRef, "SOURCES.md §G") {
		t.Fatalf("review = %+v, want enabled with §G reference", rv)
	}
	if _, ok := Registry()["ctlog"]; !ok {
		t.Fatal("ctlog not registered")
	}
}

// TestCTLogParseLeafLayout — the RFC 6962 leaf layout parser end to end.
func TestCTLogParseLeafLayout(t *testing.T) {
	leaf := ctlogTestLeaf(t, ctlogEntryX509, []string{"parse.example.com"})
	info, err := ctlogParseLeaf(leaf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(info.names) != 1 || info.names[0] != "parse.example.com" {
		t.Fatalf("names = %v", info.names)
	}
	if info.notBefore.IsZero() || info.notAfter.IsZero() || info.timestampUTC.IsZero() {
		t.Fatalf("timestamps missing: %+v", info)
	}
	if _, err := ctlogParseLeaf([]byte{1}); err == nil {
		t.Fatal("short leaf accepted")
	}
}

// TestCTLogLeafTimestampInt64Guard — gosec G115 remediation regression:
// the RFC 6962 timestamp is a uint64 millisecond count; a value beyond
// int64 must FAIL the leaf (fail-closed) instead of wrapping into a
// bogus negative time.  The exact math.MaxInt64 boundary passes the
// timestamp guard (any later failure is downstream, never the guard).
func TestCTLogLeafTimestampInt64Guard(t *testing.T) {
	leaf := make([]byte, 12)
	leaf[0] = ctlogLeafVersionV1 // version v1, signature_type byte 0
	binary.BigEndian.PutUint64(leaf[2:10], uint64(math.MaxInt64)+1)
	_, err := ctlogParseLeaf(leaf)
	if err == nil {
		t.Fatal("timestamp beyond int64 must fail the leaf, got no error")
	}
	if !strings.Contains(err.Error(), "exceeds int64 range") {
		t.Fatalf("expected the int64-range guard error, got: %v", err)
	}
	if _, isSkip := err.(ctlogSkipLeaf); isSkip {
		t.Fatal("the overflow guard is a hard leaf error, not a skip")
	}
	binary.BigEndian.PutUint64(leaf[2:10], math.MaxInt64)
	_, err = ctlogParseLeaf(leaf)
	if err == nil || strings.Contains(err.Error(), "exceeds int64 range") {
		t.Fatalf("math.MaxInt64 timestamp must pass the timestamp guard: %v", err)
	}
}
