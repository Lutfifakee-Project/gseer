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

// dataset_real_v1_integration_test.go — end-to-end acceptance against
// the REAL central dataset v1 release artifact (vendored verbatim under
// testdata/central-v1/, payload sha256 4f995d4f6103…), served through a
// loopback server with the production GitHub release path shape and
// imported through the REAL `gseer dataset update` journey (manifest
// fetch → sha256 verify → stream import).
//
// This pins the owner's evidence on dataset central v1 (269
// observations, 202 asset rows) with EXACT result counts, classifies
// the zero-result queries honestly, proves search stays LOCAL (the
// channel server receives zero requests while searching), and proves
// the v0.3.2 fixes (stale bool comparison, observed_at evidence time,
// the cert.issuer/organization/cert.subject aliases).
//
// The dataset's evidence is REAL validated pipeline output (CT log
// window, DNS/Ptr/ASN enrichment, explicit TLS :443 observation) — the
// test only READS it; nothing here pretends to be a fresh discovery.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveCentralV1 serves the vendored release artifacts with the
// production /releases/download/<tag>/<asset> path shape and counts
// every request (the search-stays-local proof reads the counter).
func serveCentralV1(t *testing.T) (manifestURL string, requests *int32) {
	t.Helper()
	var mu sync.Mutex
	var hits int32
	dir := t.TempDir()
	_ = dir
	mux := http.NewServeMux()
	asset := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
			b, err := testdataFile(name)
			if err != nil {
				http.Error(w, "missing testdata", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(b)
		}
	}
	mux.HandleFunc("/releases/download/central-dataset/gseer-dataset-manifest.json", asset("gseer-dataset-manifest.json"))
	mux.HandleFunc("/releases/download/central-dataset/gseer-dataset.ndjson.gz", asset("gseer-dataset.ndjson.gz"))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + "/releases/download/central-dataset/gseer-dataset-manifest.json", &hits
}

// countRows runs one query in JSON mode and returns the number of
// result rows (the CLI limit is raised above every expected count).
func countRows(t *testing.T, gql string) int {
	t.Helper()
	// -o json is as sticky as any root flag on the shared tree: reset it
	// so later direct-RunE tests keep their table-mode rendering.
	t.Cleanup(func() { flags.output = "" })
	out, err := executeRoot(t, "search", gql, "-o", "json", "--limit", "300")
	if err != nil {
		t.Fatalf("search %q: %v\n%s", gql, err, out)
	}
	var res struct {
		Rows  []json.RawMessage `json:"rows"`
		Query struct {
			RowCount int    `json:"row_count"`
			Mode     string `json:"mode"`
		} `json:"query"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("json %q: %v\noutput:\n%s", gql, err, out)
	}
	if len(res.Rows) != res.Query.RowCount {
		t.Fatalf("query %q: %d rows scanned, row_count says %d", gql, len(res.Rows), res.Query.RowCount)
	}
	return len(res.Rows)
}

func TestCentralDatasetV1RealEvidenceE2E(t *testing.T) {
	withDatasetEnv(t) // a fresh temp home: the import lands in a throwaway personal store
	resetSetupFlags(t)

	manifestURL, hits := serveCentralV1(t)
	t.Setenv("GSEER_DATASET_MANIFEST_URL", manifestURL)

	// The real journey: setup → dataset update (manifest → verify → import).
	if _, err := runCLI(t, "setup", "--personal"); err != nil {
		t.Fatalf("setup --personal: %v", err)
	}
	out, err := runCLI(t, "dataset", "update")
	if err != nil {
		t.Fatalf("dataset update: %v\n%s", err, out)
	}
	for _, want := range []string{"dataset v1", "269 records", "payload verified"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dataset update output missing %q:\n%s", want, out)
		}
	}
	before := *hits

	// ── The owner's evidence, with exact counts ─────────────────────
	evidence := []struct {
		gql string
		n   int
	}{
		// port=443 → 15 (owner: 15 ✓); all three spellings agree
		{"port=443", 15}, {"port==443", 15}, {`port="443"`, 15},
		// title/server → 0: dataset v1 carries NO http evidence — the
		// scan-tls observer only captures the TLS handshake.  The engine
		// is proven to match titles by the query-matrix tests; the zero
		// here is an honest DATASET coverage fact, not a parser bug.
		{`title=="Dashboard"`, 0}, {`server=="nginx"`, 0}, {"exists(http.title)", 0},
		{"ip=\"1.1.1.1\"", 1}, {`domain="example.com"`, 1}, {`host="www.example.com"`, 1},
		{`asn="13335"`, 20},
		{`protocol="https"`, 15},
		{`port="443" && protocol="https"`, 15},
		{`port="443" || port="80"`, 15},
		{`port="443" && country!="US"`, 3},
		{`(port=443 || port=80) && country="US"`, 12},
		// the owner's cert.issuer spelling works since v0.3.2 (registry alias)
		{`cert.issuer="Example CA"`, 0}, // no such issuer in v1 (honest zero)
		{`cert.issuer CONTAINS "Cloudflare"`, 4},
		{`cert.subject="example.com"`, 1},
		{`organization CONTAINS "Fastly"`, 8},
		{`tls_version="TLS 1.3"`, 15},
		{`cert.is_expired="false"`, 15},
		// v0.3.2 stale fix: the fresh index matches "false" for every row
		{`stale=="false"`, 202}, {`stale=="true"`, 0},
		// v0.3.2 observed_at: REAL evidence time (dataset generated 2026-11-18T05:38Z)
		{`observed_at > "2026-11-18T00:00:00Z"`, 202},
		{`observed_at < "2026-11-01T00:00:00Z"`, 0},
		{`observed_at > "2027-01-01T00:00:00Z"`, 0},
		// breadth on the real corpus
		{`country="US"`, 47},
		{`sources CONTAINS "central-ctlog"`, 64},
		{`ip IN_CIDR "1.1.1.0/24"`, 1},
		{`hostname *= "*.example.*"`, 3},
		{`asset_kind="domain"`, 14},
		{`is_ipv6="true"`, 24},
		{`"cloudflare"`, 28},
		{"asn >= 13335 && asn <= 64512", 49},
		{"last_seen > \"2026-01-01T00:00:00Z\"", 202},
	}
	for _, tc := range evidence {
		if got := countRows(t, tc.gql); got != tc.n {
			t.Errorf("evidence query %q = %d rows, want %d", tc.gql, got, tc.n)
		}
	}

	// ── Search stays LOCAL: zero channel requests while searching ───
	if *hits != before {
		t.Errorf("the channel server received %d new requests during searching; search must never touch the network", *hits-before)
	}

	// ── observed_at is the evidence time, not the import stamp ──────
	out, err = executeRoot(t, "search", `ip="1.1.1.1"`, "-o", "json", "--limit", "5")
	if err != nil {
		t.Fatalf("json search: %v\n%s", err, out)
	}
	var res struct {
		Rows []struct {
			ObservedAt *string `json:"observed_at"`
			LastSeen   string  `json:"last_seen"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res.Rows) != 1 {
		t.Fatalf("json rows: %v (%d rows)\n%s", err, len(res.Rows), out)
	}
	if res.Rows[0].ObservedAt == nil {
		t.Fatal("observed_at missing from the JSON row")
	}
	if ot, perr := time.Parse(time.RFC3339Nano, *res.Rows[0].ObservedAt); perr != nil || ot.Before(time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC)) || ot.After(time.Date(2026, 11, 18, 6, 0, 0, 0, time.UTC)) {
		t.Errorf("observed_at = %v, want the real evidence window (2026-11-18T05:38Z ±)", *res.Rows[0].ObservedAt)
	}
	if lt, perr := time.Parse(time.RFC3339Nano, res.Rows[0].LastSeen); perr == nil && lt.Sub(time.Now()).Abs() > time.Hour {
		t.Errorf("last_seen = %v, want the import stamp (~now)", res.Rows[0].LastSeen)
	}

	// ── invalid syntax fails LOUD with an informative error ─────────
	code, called := captureExit(t, func() {
		out, _ = executeRoot(t, "search", `nosuchfield="x"`)
	})
	if !called || code != ExitInvalidInput || !strings.Contains(out, "nosuchfield") {
		t.Errorf("unknown field must exit %d naming the field, called=%v code=%d out=\n%s", ExitInvalidInput, called, code, out)
	}
}

// testdataFile reads a vendored artifact (go:embed cannot see files in
// a parent-relative directory; an explicit read keeps the artifact
// byte-identical).
func testdataFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", "central-v1", name))
}
