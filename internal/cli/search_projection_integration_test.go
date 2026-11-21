// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

//go:build integration

package cli

// search_projection_integration_test.go — the v0.3.2-r2 owner finding,
// rendered end to end through the CLI over the fixture corpus: with a
// custom --fields projection, JSON/YAML/CSV/NDJSON/table all carry the
// mandatory identity/metadata block plus exactly the selected fields,
// and cursor pagination stays correct.

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func setupProjectionCLI(t *testing.T) string {
	t.Helper()
	t.Cleanup(func() {
		flags.output = ""
		searchFlagsReset()
	})
	dsn, cleanup := cliTestDB(t)
	t.Cleanup(cleanup)
	cfgFile := writeFixtureCLIConfig(t, dsn, true)
	runSetupFixtureAction(t, "load-fixtures", dsn, cfgFile, "")
	return cfgFile
}

// payloadCut drops the operator-credential status banner the CLI prints
// ahead of the payload in the raw-DSN test config.  The banner is
// bracket-prefixed with indented continuation lines; the payload starts
// at the first '{' (json/ndjson), a "rows:" key (yaml), or the
// "row_id," csv header.  No match → the output is returned unchanged
// (e.g. table mode, where the banner does not disturb Contains checks).
func payloadCut(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "rows:") || strings.HasPrefix(t, "row_id,") {
			return strings.Join(lines[i:], "\n")
		}
	}
	return s
}

func TestSearchCustomProjectionFormatsE2E(t *testing.T) {
	cfgFile := setupProjectionCLI(t)
	const fields = "ip,tls_version"

	// ---- JSON: metadata populated; requested kept; port absent ----
	out, err := executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "2", "-o", "json")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("json search: %v\n%s", err, out)
	}
	var doc struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json parse: %v\n%s", err, out)
	}
	if len(doc.Rows) == 0 {
		t.Fatalf("no rows in JSON output:\n%s", out)
	}
	for _, r := range doc.Rows {
		for _, k := range []string{"row_id", "row_kind", "asset_id", "asset_kind", "asset_value", "first_seen", "last_seen"} {
			if v, ok := r[k]; !ok || v == nil {
				t.Errorf("JSON row missing mandatory key %q: %v", k, r)
			}
		}
		if r["row_kind"] != "service" {
			t.Errorf("row_kind = %v, want service", r["row_kind"])
		}
		if av, _ := r["asset_value"].(string); av == "" {
			t.Errorf("asset_value empty: %v", r)
		}
		if fs, _ := r["first_seen"].(string); strings.HasPrefix(fs, "0001-01-01") {
			t.Errorf("first_seen zeroed: %v", fs)
		}
		if _, ok := r["ip"]; !ok {
			t.Errorf("requested key ip missing from JSON row")
		}
		if _, ok := r["port"]; ok {
			t.Errorf("unrequested port key leaked into JSON row: %v", r)
		}
	}

	// ---- YAML: the SAME wire keys as JSON (JSON round-trip contract) ----
	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "2", "-o", "yaml")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("yaml search: %v\n%s", err, out)
	}
	var ydoc struct {
		Rows []map[string]any `yaml:"rows"`
	}
	if err := yaml.Unmarshal([]byte(out), &ydoc); err != nil {
		t.Fatalf("yaml parse: %v\n%s", err, out)
	}
	if len(ydoc.Rows) == 0 {
		t.Fatalf("no rows in YAML output:\n%s", out)
	}
	for _, r := range ydoc.Rows {
		for _, k := range []string{"row_id", "row_kind", "asset_value", "first_seen"} {
			if v, ok := r[k]; !ok || v == nil {
				t.Errorf("YAML row missing mandatory key %q: %v", k, r)
			}
		}
		if av, _ := r["asset_value"].(string); av == "" {
			t.Errorf("YAML asset_value empty: %v", r)
		}
		if _, ok := r["port"]; ok {
			t.Errorf("unrequested port key leaked into YAML row: %v", r)
		}
	}

	// ---- CSV: header = mandatory block + requested fields ----
	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "2", "-o", "csv")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("csv search: %v\n%s", err, out)
	}
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v\n%s", err, out)
	}
	if len(recs) < 2 {
		t.Fatalf("csv rows: %d records\n%s", len(recs), out)
	}
	header := recs[0]
	colIdx := map[string]int{}
	for i, c := range header {
		colIdx[c] = i
	}
	for _, col := range []string{"row_id", "row_kind", "asset_id", "asset_kind", "asset_value", "ip", "tls_version", "first_seen", "last_seen", "observed_at", "stale"} {
		if _, ok := colIdx[col]; !ok {
			t.Errorf("csv header missing %q: %v", col, header)
		}
	}
	if _, ok := colIdx["port"]; ok {
		t.Errorf("unrequested port column in csv header: %v", header)
	}
	for _, rec := range recs[1:] {
		if rec[colIdx["asset_value"]] == "" {
			t.Errorf("csv asset_value empty: %v", rec)
		}
		if rec[colIdx["row_id"]] == "0" || rec[colIdx["row_id"]] == "" {
			t.Errorf("csv row_id zeroed: %v", rec)
		}
		if strings.HasPrefix(rec[colIdx["first_seen"]], "0001-01-01") {
			t.Errorf("csv first_seen zeroed: %v", rec)
		}
	}

	// ---- NDJSON: one compact JSON object per row ----
	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "2", "-o", "ndjson")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("ndjson search: %v\n%s", err, out)
	}
	nLines := 0
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		nLines++
		var r map[string]any
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("ndjson line parse: %v\nline: %s", err, ln)
		}
		if v, _ := r["row_id"].(float64); v == 0 {
			t.Errorf("ndjson row_id zeroed: %s", ln)
		}
		if av, _ := r["asset_value"].(string); av == "" {
			t.Errorf("ndjson asset_value empty: %s", ln)
		}
	}
	if nLines == 0 {
		t.Fatalf("empty ndjson output:\n%s", out)
	}

	// ---- table (default): renders the fixture asset values ----
	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "-o", "table")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("table search: %v\n%s", err, out)
	}
	if !strings.Contains(out, "203.0.113.10") {
		t.Errorf("table output missing the fixture asset value:\n%s", out)
	}

	// ---- default projection unchanged: port key present without ----
	// ---- --fields ----
	// searchFlagsReset clears the sticky --fields value: cobra flag
	// values persist across Execute() calls on the shared RootCmd (the
	// documented seam; without it this "default" run would inherit the
	// custom projection set by the blocks above).
	searchFlagsReset()
	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--limit", "1", "-o", "json")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("default json search: %v\n%s", err, out)
	}
	var ddoc struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &ddoc); err != nil {
		t.Fatalf("default json parse: %v", err)
	}
	if len(ddoc.Rows) == 0 || ddoc.Rows[0]["port"] == nil {
		t.Errorf("default projection lost the port key:\n%s", out)
	}
	if ddoc.Rows[0]["row_id"] == nil {
		t.Errorf("default projection lost row_id:\n%s", out)
	}

	// ---- unknown format fails fast with exit 2 ----
	guard := pinExitFunc(t)
	t.Cleanup(func() { flags.output = "" })
	_, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "-o", "toml")
	if err != nil {
		t.Fatalf("unknown format returned error instead of the exit seam: %v", err)
	}
	if guard.called == nil || *guard.called != ExitInvalidInput {
		t.Errorf("unknown output format: want exit %d, got %v", ExitInvalidInput, guard.called)
	}
}

func TestSearchCustomProjectionCursorE2E(t *testing.T) {
	cfgFile := setupProjectionCLI(t)
	const fields = "ip,tls_version"

	out, err := executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "1", "-o", "json")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("page1: %v\n%s", err, out)
	}
	var page1 struct {
		Rows    []map[string]any `json:"rows"`
		Cursor  string           `json:"next_cursor"`
		HasMore bool             `json:"has_more"`
	}
	if err := json.Unmarshal([]byte(out), &page1); err != nil {
		t.Fatalf("page1 parse: %v", err)
	}
	if len(page1.Rows) != 1 || !page1.HasMore || page1.Cursor == "" {
		t.Fatalf("page1 shape: rows=%d has_more=%v cursor=%q", len(page1.Rows), page1.HasMore, page1.Cursor)
	}
	r1id, _ := page1.Rows[0]["row_id"].(float64)

	out, err = executeRoot(t, "--config", cfgFile, "search", `port == 443`, "--fields", fields, "--limit", "1", "--cursor", page1.Cursor, "-o", "json")
	out = payloadCut(out)
	if err != nil {
		t.Fatalf("page2: %v\n%s", err, out)
	}
	var page2 struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(out), &page2); err != nil {
		t.Fatalf("page2 parse: %v", err)
	}
	if len(page2.Rows) == 0 {
		t.Fatalf("page2 empty:\n%s", out)
	}
	r := page2.Rows[0]
	if r["row_id"] == r1id {
		t.Errorf("page2 repeated page1 row %v (broken keyset)", r1id)
	}
	if r["row_kind"] != "service" {
		t.Errorf("page2 row_kind = %v, want service", r["row_kind"])
	}
	if av, _ := r["asset_value"].(string); av == "" {
		t.Errorf("page2 asset_value empty: %v", r)
	}
	if fs, _ := r["first_seen"].(string); strings.HasPrefix(fs, "0001-01-01") {
		t.Errorf("page2 first_seen zeroed: %v", r)
	}
}
