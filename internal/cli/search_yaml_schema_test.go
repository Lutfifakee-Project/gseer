// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"gopkg.in/yaml.v3"
)

// r3.2 finding #2 regression tests — YAML and JSON must share ONE
// serialization contract: identical field names (metadata index,
// query metadata, nested sort fields), identical types, and identical
// null semantics, parseable by the standard YAML parser.

func yamlSchemaFixture() *search.Result {
	exp := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	return &search.Result{
		Rows: []search.Row{
			{
				RowID: 15, RowKind: "service", AssetID: 12, AssetKind: "ip",
				AssetValue: "203.0.113.10", IP: ptr2s("203.0.113.10"),
				Port: ptr2(443), Transport: ptr2s("tcp"), Protocol: ptr2s("https"),
				TLSVersion:       ptr2s("TLSv1.3"),
				TLSCertSubjectCN: ptr2s("example.com"),
				TLSCertIssuerCN:  ptr2s("R3"),
				TLSCertExpiry:    &exp,
				TLSCertSerial:    ptr2s("04:aa:bb"),
				TLSCertSansDNS:   ptr2s("example.com,www.example.com"),
				FirstSeen:        t1, LastSeen: t1,
			},
			{
				// Row with absent optional fields (null/absence parity).
				RowID: 16, RowKind: "asset-only", AssetID: 13, AssetKind: "domain",
				AssetValue: "example.org", Domain: ptr2s("example.org"),
				FirstSeen: t1, LastSeen: t1,
			},
		},
		NextCursor: "eyJ2IjoxfQ==",
		HasMore:    true,
		Query: search.QueryInfo{
			GQL:       "port=443",
			Mode:      "service",
			Branch:    "scan",
			Limit:     20,
			TimeoutMs: 250,
			Sort:      []planner.SortSpec{{Field: "last_seen", Direction: planner.DirDesc}},
			TookMs:    3,
			RowCount:  2,
			Fixtures:  true,
		},
		Index: &search.IndexMeta{
			Assets: 61, Services: 269, Observations: 269, FixtureObs: 269,
			LastObserved: &t1, FixtureOnly: true, Empty: false,
		},
		Notice: "",
	}
}

func renderEnvelopeJSON(t *testing.T, res *search.Result) map[string]any {
	t.Helper()
	var jbuf bytes.Buffer
	renderResult(&jbuf, res, "json")
	var j map[string]any
	if err := json.Unmarshal(jbuf.Bytes(), &j); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	return j
}

func renderEnvelopeYAML(t *testing.T, res *search.Result) map[string]any {
	t.Helper()
	var ybuf bytes.Buffer
	renderResultYAML(&ybuf, res)
	var y map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(ybuf.Bytes()))
	if err := dec.Decode(&y); err != nil {
		t.Fatalf("standard yaml parse: %v", err)
	}
	return y
}

// assertKeyParity walks both envelopes and requires, at EVERY object
// node, the exact same key set; scalars must agree in kind (number,
// bool, string, null).  Absent-on-both-sides counts as parity.
func assertKeyParity(t *testing.T, path string, j, y any) {
	t.Helper()
	switch jv := j.(type) {
	case map[string]any:
		yv, ok := y.(map[string]any)
		if !ok {
			t.Fatalf("%s: yaml node is %T, want map", path, y)
		}
		if len(jv) != len(yv) {
			t.Fatalf("%s: key count differs json=%d yaml=%d\njson keys: %v\nyaml keys: %v",
				path, len(jv), len(yv), keysOf(jv), keysOf(yv))
		}
		for k, jchild := range jv {
			ychild, ok := yv[k]
			if !ok {
				t.Fatalf("%s: key %q missing from YAML (json keys %v)", path, k, keysOf(jv))
			}
			assertKeyParity(t, path+"."+k, jchild, ychild)
		}
	case []any:
		yv, ok := y.([]any)
		if !ok {
			t.Fatalf("%s: yaml node is %T, want list", path, y)
		}
		if len(jv) != len(yv) {
			t.Fatalf("%s: list length differs json=%d yaml=%d", path, len(jv), len(yv))
		}
		for i := range jv {
			assertKeyParity(t, path+"[]", jv[i], yv[i])
		}
	default:
		if isNull(j) != isNull(y) {
			t.Fatalf("%s: null parity broken json=%v yaml=%v", path, j, y)
		}
		if isNumber(j) != isNumber(y) {
			t.Fatalf("%s: number-kind parity broken json=%v(%T) yaml=%v(%T)", path, j, j, y, y)
		}
		if isBool(j) != isBool(y) {
			t.Fatalf("%s: bool parity broken json=%v(%T) yaml=%v(%T)", path, j, j, y, y)
		}
	}
}

func isNull(v any) bool { return v == nil }
func isBool(v any) bool { _, ok := v.(bool); return ok }
func isNumber(v any) bool {
	switch v.(type) {
	case float64, float32, int, int64, int32, json.Number:
		return true
	}
	return false
}
func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestYAMLJSONKeyParity(t *testing.T) {
	res := yamlSchemaFixture()
	j := renderEnvelopeJSON(t, res)
	y := renderEnvelopeYAML(t, res)
	assertKeyParity(t, "envelope", j, y)
}

func TestYAMLMetadataFieldNames(t *testing.T) {
	res := yamlSchemaFixture()
	y := renderEnvelopeYAML(t, res)
	idx, ok := y["index"].(map[string]any)
	if !ok {
		t.Fatalf("yaml index missing: %v", keysOf(y))
	}
	for _, want := range []string{"fixture_observations", "last_observed_at", "fixture_only", "empty", "assets", "services", "observations"} {
		if _, ok := idx[want]; !ok {
			t.Fatalf("yaml index key %q missing — yaml keys: %v", want, keysOf(idx))
		}
	}
	for _, bad := range []string{"fixtureobs", "lastobserved"} {
		if _, ok := idx[bad]; ok {
			t.Fatalf("yaml index still uses drifted key %q", bad)
		}
	}
	q, ok := y["query"].(map[string]any)
	if !ok {
		t.Fatalf("yaml query missing: %v", keysOf(y))
	}
	for _, want := range []string{"timeout_ms", "row_count", "took_ms", "gql", "mode", "branch", "limit", "sort", "fixtures"} {
		if _, ok := q[want]; !ok {
			t.Fatalf("yaml query key %q missing — yaml keys: %v", want, keysOf(q))
		}
	}
	for _, bad := range []string{"timeoutms", "rowcount", "tookms"} {
		if _, ok := q[bad]; ok {
			t.Fatalf("yaml query still uses drifted key %q", bad)
		}
	}
}

func TestYAMLNestedSortFieldsParity(t *testing.T) {
	res := yamlSchemaFixture()
	j := renderEnvelopeJSON(t, res)
	y := renderEnvelopeYAML(t, res)
	jq := j["query"].(map[string]any)
	yq := y["query"].(map[string]any)
	js, ok := jq["sort"].([]any)
	if !ok || len(js) == 0 {
		t.Fatalf("json sort missing: %v", jq)
	}
	ys, ok := yq["sort"].([]any)
	if !ok || len(ys) == 0 {
		t.Fatalf("yaml sort missing: %v", yq)
	}
	j0 := js[0].(map[string]any)
	y0 := ys[0].(map[string]any)
	if len(j0) != len(y0) {
		t.Fatalf("nested sort key sets differ json=%v yaml=%v", keysOf(j0), keysOf(y0))
	}
	for k, v := range j0 {
		if _, ok := y0[k]; !ok {
			t.Fatalf("nested sort key %q missing from YAML (json keys %v)", k, keysOf(y0))
		}
		assertKeyParity(t, "sort[0]."+k, v, y0[k])
	}
}

func TestYAMLValueTypes(t *testing.T) {
	res := yamlSchemaFixture()
	j := renderEnvelopeJSON(t, res)
	y := renderEnvelopeYAML(t, res)
	// bool
	if _, ok := y["has_more"].(bool); !ok {
		t.Fatalf("yaml has_more not bool: %T", y["has_more"])
	}
	if j["has_more"].(bool) != y["has_more"].(bool) {
		t.Fatal("has_more value differs")
	}
	// number
	if n, ok := y["count"].(int); !ok || n != 2 {
		t.Fatalf("yaml count = %v(%T), want int 2", y["count"], y["count"])
	}
	// string
	if s, ok := y["next_cursor"].(string); !ok || s != "eyJ2IjoxfQ==" {
		t.Fatalf("yaml next_cursor = %v", y["next_cursor"])
	}
	// timestamp: identical RFC3339 string on both surfaces
	jrow := j["rows"].([]any)[0].(map[string]any)
	yrow := y["rows"].([]any)[0].(map[string]any)
	if jrow["first_seen"] != yrow["first_seen"] {
		t.Fatalf("first_seen differs json=%v yaml=%v", jrow["first_seen"], yrow["first_seen"])
	}
	yidx := y["index"].(map[string]any)
	if ts, ok := yidx["last_observed_at"].(string); !ok || ts != j["index"].(map[string]any)["last_observed_at"] {
		t.Fatalf("last_observed_at differs yaml=%v", yidx["last_observed_at"])
	}
	// null/absence parity: row 2 has no TLS fields (omitempty) — the
	// key must be absent on BOTH surfaces, and the parity walker
	// proves any future null emission stays consistent.
	yrow2 := y["rows"].([]any)[1].(map[string]any)
	if _, ok := yrow2["tls_version"]; ok {
		t.Fatalf("absent tls_version must not fabricate a key in yaml: %v", keysOf(yrow2))
	}
	jrow2 := j["rows"].([]any)[1].(map[string]any)
	if _, ok := jrow2["tls_version"]; ok {
		t.Fatalf("absent tls_version must not fabricate a key in json")
	}
}

func TestYAMLParsesWithStandardParser(t *testing.T) {
	var ybuf bytes.Buffer
	renderResultYAML(&ybuf, yamlSchemaFixture())
	var doc map[string]any
	if err := yaml.Unmarshal(ybuf.Bytes(), &doc); err != nil {
		t.Fatalf("standard yaml parser rejected the envelope: %v", err)
	}
	if len(doc) == 0 {
		t.Fatal("yaml document empty")
	}
	if !strings.Contains(ybuf.String(), "fixture_observations") {
		t.Fatalf("yaml output lost the JSON-contract key: %s", ybuf.String()[:200])
	}
}
