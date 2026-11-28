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

// topdomains_test.go — unit tests for the public-popularity domain
// list connector (R39 P1): row parsing honesty (published numbers
// copied verbatim, implausible rows rejected), full/budgeted/resumed
// line-offset walks, and the cursor round trip.
package collect

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const topdomainsSample = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,PrevGlobalRank,PrevTldRank\n" +
	"1,1,google.com,com,502976,2160843,1,1\n" +
	"2,2,facebook.com,com,462678,2131415,2,2\n" +
	"3,3,youtube.com,com,419814,1747686,3,3\n" +
	"4,4,example.org,org,1200,4500,4,4\n" +
	"not-a-rank,broken.com,com,1,2,3,4\n" +
	"5,5,short.example,com,10\n" +
	"6,6,mixed-case.Example.COM,com,77,8800,6,6\n"

func TestTopdomainsRowParsesPublishedNumbers(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	f, ok := topdomainsRow("1,1,google.com,com,502976,2160843,1,1", now)
	if !ok {
		t.Fatal("valid row rejected")
	}
	if f.AssetKind != "domain" || f.Value != "google.com" {
		t.Fatalf("wrong asset: kind=%q value=%q", f.AssetKind, f.Value)
	}
	if f.Confidence != "medium" {
		t.Fatalf("a published popularity list is not a direct observation: confidence=%q", f.Confidence)
	}
	td, _ := f.Extra["topdomains"].(map[string]any)
	if td == nil {
		t.Fatal("missing topdomains evidence object")
	}
	if td["rank"] != 1 || td["refnets"] != 502976 || td["refips"] != 2160843 {
		t.Fatalf("published numbers not copied verbatim: %+v", td)
	}
	if td["tld"] != "com" {
		t.Fatalf("tld: %v", td["tld"])
	}
	if attr, _ := td["attribution"].(string); !strings.Contains(attr, "Majestic") {
		t.Fatalf("attribution missing from evidence: %v", td["attribution"])
	}
}

func TestTopdomainsRowRejectsImplausibleRows(t *testing.T) {
	now := time.Now().UTC()
	for _, line := range []string{
		"not-a-rank,broken.com,com,1,2,3,4", // rank is not a number
		"5,5,short.example,com,10",          // too few fields
		",, ,, ,, ",                         // empty
		"7,7,nodot,com,1,2,3,4",             // not a domain
	} {
		if _, ok := topdomainsRow(line, now); ok {
			t.Fatalf("implausible row accepted: %q", line)
		}
	}
}

func TestTopdomainsParseFullConsume(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	facts, offset, total, invalid, err := topdomainsParse(context.Background(), strings.NewReader(topdomainsSample), 0, 100, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(facts) != 5 { // 7 data lines, 2 implausible
		t.Fatalf("facts: got %d want 5", len(facts))
	}
	if invalid != 2 {
		t.Fatalf("invalid lines: got %d want 2", invalid)
	}
	if total != 7 {
		t.Fatalf("total data lines: got %d want 7", total)
	}
	if offset != 7 {
		t.Fatalf("offset at EOF: got %d want 7", offset)
	}
	if facts[0].Value != "google.com" || facts[4].Value != "mixed-case.example.com" {
		t.Fatalf("value canonicalization: %q, %q", facts[0].Value, facts[4].Value)
	}
}

func TestTopdomainsParseBudgetTruncates(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	facts, offset, total, _, err := topdomainsParse(context.Background(), strings.NewReader(topdomainsSample), 0, 3, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(facts) != 3 {
		t.Fatalf("facts under budget: got %d want 3", len(facts))
	}
	if total != -1 {
		t.Fatalf("truncated run must not claim a total: got %d want -1", total)
	}
	if offset != 4 {
		t.Fatalf("resume offset: got %d want 4 (the line the budget stopped at)", offset)
	}
}

func TestTopdomainsParseResumeSkipsConsumedLines(t *testing.T) {
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	facts, _, _, _, err := topdomainsParse(context.Background(), strings.NewReader(topdomainsSample), 4, 100, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Data lines 1-4 were consumed by an earlier run; lines 5-7 remain
	// (line 5 is implausible, lines 6-7... sample has 7 data lines:
	// ranks 1-4, broken, short, mixed-case → resume yields mixed-case).
	if len(facts) != 1 || facts[0].Value != "mixed-case.example.com" {
		t.Fatalf("resume facts: %+v", facts)
	}
}

func TestTopdomainsCursorRoundTripAndEndpointReset(t *testing.T) {
	empty, ok := parseTopdomainsCursor("")
	if ok || empty.Offset != 0 {
		t.Fatalf("empty cursor: %+v ok=%v", empty, ok)
	}
	bad, ok := parseTopdomainsCursor("{not json")
	if ok || bad.Offset != 0 {
		t.Fatalf("bad cursor: %+v ok=%v", bad, ok)
	}
	enc, _ := json.Marshal(topdomainsCursor{Offset: 42, Endpoint: "https://example.test/list.csv"})
	cur, ok := parseTopdomainsCursor(string(enc))
	if !ok || cur.Offset != 42 || cur.Endpoint != "https://example.test/list.csv" {
		t.Fatalf("round trip: %+v ok=%v", cur, ok)
	}
}

func TestTopdomainsConnectorRegistered(t *testing.T) {
	if _, ok := Registry()["topdomains"]; !ok {
		t.Fatal("topdomains connector not registered")
	}
}
