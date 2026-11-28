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

// pdns_test.go — offline proofs for the passive-DNS connector: both
// providers parse honestly against loopback fakes, the free-tier error
// message is an error (never a hostname), per-seed failures do not sink
// the others' answers, and the hostname dedupe is per-pass.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pdnsTestCtx(t *testing.T, server *httptest.Server, cfg SourceConfig) Ctx {
	t.Helper()
	if cfg.Endpoint == "" {
		cfg.Endpoint = server.URL
	}
	return Ctx{
		Context: context.Background(),
		Source:  SourceRef{ID: 7, Name: "pdns-test"},
		Config:  cfg,
		Limit:   100,
		Client:  NewClient(ClientConfig{RequestsPerSecond: 1000, Timeout: 2 * time.Second}),
		Now:     func() time.Time { return time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC) },
	}
}

func TestPDNSHackertargetParsesHostsearchLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if got := "/?q=example.test"; got != "/?q=example.test" {
			t.Errorf("unexpected query path %s", got)
		}
		_, _ = w.Write([]byte("www.example.test,203.0.113.10\napi.example.test,203.0.113.11\n\n"))
	}))
	defer server.Close()

	batch, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		Seeds: []string{"example.test"}, Provider: "hackertarget",
	}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(batch.Raws) != 2 {
		t.Fatalf("raws = %d, want 2 (%+v)", len(batch.Raws), batch.Raws)
	}
	first := batch.Raws[0]
	if first.AssetKind != "hostname" || first.Value != "www.example.test" {
		t.Fatalf("first raw = %+v", first)
	}
	if first.Confidence != "medium" {
		t.Fatalf("confidence = %q, want medium (third-party history)", first.Confidence)
	}
	ev, _ := first.Extra["pdns"].(map[string]any)
	if ev == nil || ev["provider"] != "hackertarget" || ev["address"] != "203.0.113.10" {
		t.Fatalf("evidence = %+v", ev)
	}
	if batch.Notes["hosts"] != 2 || batch.Notes["provider_hackertarget"] != 2 {
		t.Fatalf("notes = %v", batch.Notes)
	}
}

func TestPDNSHackertargetFreeTierMessageIsAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The free tier answers its quota message as plain text.
		_, _ = w.Write([]byte("error check API count exceeded your quota"))
	}))
	defer server.Close()

	_, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		Seeds: []string{"example.test"}, Provider: "hackertarget",
	}))
	if err == nil || !strings.Contains(err.Error(), "all 1 seed lookups failed") {
		t.Fatalf("quota message must fail the (single) seed, got %v", err)
	}
}

func TestPDNSOneFailedSeedDoesNotSinkTheOthers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "bad.test") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("ok.example.test,203.0.113.99\n"))
	}))
	defer server.Close()

	batch, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		Seeds: []string{"bad.test", "good.test"}, Provider: "hackertarget",
	}))
	if err != nil {
		t.Fatalf("one failed seed must not fail the pass: %v", err)
	}
	if len(batch.Raws) != 1 || batch.Raws[0].Value != "ok.example.test" {
		t.Fatalf("raws = %+v", batch.Raws)
	}
}

func TestPDNSWaybackExtractsHostnamesFromArchivedURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[["original"],
["https://www.example.test/docs/page"],
["http://old.example.test/"],
["http://www.example.test/other"]]`))
	}))
	defer server.Close()

	batch, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		Seeds: []string{"example.test"}, Provider: "wayback",
	}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(batch.Raws) != 2 { // www.example.test dedupes across rows 1 and 3
		t.Fatalf("raws = %d, want 2 (%+v)", len(batch.Raws), batch.Raws)
	}
	values := map[string]bool{}
	for _, raw := range batch.Raws {
		values[raw.Value] = true
		ev, _ := raw.Extra["pdns"].(map[string]any)
		if ev == nil || ev["provider"] != "wayback" || ev["original"] == "" {
			t.Fatalf("evidence = %+v", ev)
		}
	}
	if !values["www.example.test"] || !values["old.example.test"] {
		t.Fatalf("hosts = %v", values)
	}
	if batch.Notes["provider_wayback"] != 2 {
		t.Fatalf("notes = %v", batch.Notes)
	}
}

func TestPDNSUnknownProviderIsFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()

	_, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		Seeds: []string{"example.test"}, Provider: "shady-provider",
	}))
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("unknown provider must be fatal, got %v", err)
	}
}

func TestPDNSEmptySeedsIsAZeroWorkBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no seeds must mean no provider traffic")
	}))
	defer server.Close()

	batch, err := pdnsConnector{}.Collect(pdnsTestCtx(t, server, SourceConfig{
		SeedMode: "config",
	}))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(batch.Raws) != 0 || batch.Notes["seeds"] != 0 {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestPDNSRegistryEntryAndReview(t *testing.T) {
	c, ok := Registry()["pdns"]
	if !ok {
		t.Fatal("pdns is not registered")
	}
	r := c.Review()
	if r.Verdict != ReviewEnabled || r.DocRef == "" {
		t.Fatalf("review = %+v", r)
	}
}
