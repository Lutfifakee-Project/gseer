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

// search_format_consistency_test.go — R3 format-consistency proof: the
// SAME result rendered as JSON, CSV, and NDJSON must agree on the row
// set — same rows, same key fields (kind/value/port), no row lost or
// invented by any renderer.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/search"
)

func formatConsistencyResult() *search.Result {
	p443, p80 := 443, 80
	ip7, ip8 := "198.51.100.7", "198.51.100.8"
	dom := "bench.example"
	org := "Bench Telecom"
	return &search.Result{
		Rows: []search.Row{
			{RowKind: "service", AssetKind: "ip", AssetValue: ip7, IP: &ip7, Port: &p443, Protocol: ptrStr("https"), ASNOrg: &org},
			{RowKind: "service", AssetKind: "ip", AssetValue: ip7, IP: &ip7, Port: &p80, Protocol: ptrStr("http")},
			{RowKind: "asset-only", AssetKind: "domain", AssetValue: dom, Domain: &dom},
			{RowKind: "asset-only", AssetKind: "ip", AssetValue: ip8, IP: &ip8, Port: nil},
		},
		Query: search.QueryInfo{RowCount: 4, GQL: `ip IN_CIDR "198.51.100.0/24" || domain=="bench.example"`, Mode: "asset"},
	}
}

func ptrStr(s string) *string { return &s }

// rowKey extracts the identity triple a format must carry (the port as
// its raw string — "" when absent — so every renderer compares equal).
func rowKey(kind, value, port string) string {
	return kind + "|" + value + "|" + port
}

func TestSearchFormatConsistency(t *testing.T) {
	res := formatConsistencyResult()
	want := map[string]bool{}
	for _, r := range res.Rows {
		p := ""
		if r.Port != nil {
			p = portStr(r.Port)
		}
		want[rowKey(r.AssetKind, r.AssetValue, p)] = true
	}
	if len(want) != 4 {
		t.Fatalf("fixture rows are not unique: %v", want)
	}

	restore := flags.output
	defer func() { flags.output = restore }()

	// JSON: the full envelope, rows carry every identity triple.
	flags.output = "json"
	var bufJSON bytes.Buffer
	renderResult(&bufJSON, res, true, nil)
	var envelope struct {
		Rows []search.Row `json:"rows"`
	}
	if err := json.Unmarshal(bufJSON.Bytes(), &envelope); err != nil {
		t.Fatalf("json render is not valid JSON: %v", err)
	}
	if len(envelope.Rows) != 4 {
		t.Fatalf("json rows = %d, want 4", len(envelope.Rows))
	}

	// CSV: header + one RFC 4180 row per result row; the identity
	// columns (asset_kind, asset_value, port) must round-trip.
	flags.output = "csv"
	var bufCSV bytes.Buffer
	renderResult(&bufCSV, res, false, nil)
	cr := csv.NewReader(strings.NewReader(bufCSV.String()))
	records, err := cr.ReadAll()
	if err != nil {
		t.Fatalf("csv render is not valid RFC 4180: %v", err)
	}
	if len(records) != 5 { // header + 4 rows
		t.Fatalf("csv rows (with header) = %d, want 5", len(records))
	}
	var kindIdx, valueIdx, portIdx = -1, -1, -1
	for i, col := range records[0] {
		switch col {
		case "asset_kind":
			kindIdx = i
		case "asset_value":
			valueIdx = i
		case "port":
			portIdx = i
		}
	}
	if kindIdx < 0 || valueIdx < 0 || portIdx < 0 {
		t.Fatalf("csv header missing identity columns: %v", records[0])
	}
	gotCSV := map[string]bool{}
	for _, rec := range records[1:] {
		port := rec[portIdx]
		if port == "-" { // the CSV renderer's absent-value marker
			port = ""
		} else if port != "" {
			if _, err = atoi2(port); err != nil {
				t.Fatalf("csv port %q does not parse: %v", port, err)
			}
		}
		gotCSV[rowKey(rec[kindIdx], rec[valueIdx], port)] = true
	}

	// NDJSON: one compact object per row, same identity triples.
	flags.output = "ndjson"
	var bufND bytes.Buffer
	renderResult(&bufND, res, false, nil)
	lines := strings.Split(strings.TrimSpace(bufND.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("ndjson lines = %d, want 4", len(lines))
	}
	gotND := map[string]bool{}
	for _, line := range lines {
		var r search.Row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("ndjson line is not valid JSON: %v", err)
		}
		p := ""
		if r.Port != nil {
			p = portStr(r.Port)
		}
		gotND[rowKey(r.AssetKind, r.AssetValue, p)] = true
	}

	for name, got := range map[string]map[string]bool{"json (envelope)": nil, "csv": gotCSV, "ndjson": gotND} {
		if name == "json (envelope)" {
			got = map[string]bool{}
			for _, r := range envelope.Rows {
				p := ""
				if r.Port != nil {
					p = portStr(r.Port)
				}
				got[rowKey(r.AssetKind, r.AssetValue, p)] = true
			}
		}
		if !equalSets(want, got) {
			t.Fatalf("%s row set diverges:\n want %v\n got  %v", name, want, got)
		}
	}
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// portStr renders a row port as its raw string ("" when absent).
func portStr(p *int) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}

// atoi2 is a tiny local helper (itoa2 exists in the renderer file).
func atoi2(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, nil
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
