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

// topdomains.go — the public-popularity domain list connector (R39 P1).
//
// topdomains ingests a PUBLIC domain-popularity list as first-class
// domain assets — the honest way to feed the DNS and CT connectors a
// real target corpus without scanning anyone: the domains are the
// list's own publication (Majestic publishes the file for free
// download; each row is what the operator may legitimately point
// lookups at).
//
// Honesty contract (R39 P1):
//   - This is a SNAPSHOT source.  The file is a periodic aggregate;
//     GSEER records the fetch time as observed_at and the list's own
//     attribution in every evidence object.  No per-record timestamp
//     exists upstream — none is invented.
//   - Rank/RefSubNets/RefIPs are the LIST's published numbers, copied
//     verbatim into evidence — not re-measured claims.
//   - Ingestion is line-offset checkpointed (the same composite-cursor
//     pattern as the delegated connector): a run that hits its budget
//     resumes at the line offset; the header line is always consumed.
//
// Politeness: ONE request per run against a file the publisher
// distributes for that purpose; the shared client's rate limits and
// body caps apply (a dedicated long-window client like the delegated
// connector's, because the file is far larger than the JSON-grade
// cap).
package collect

// topdomains ingests a PUBLIC domain-popularity list as first-class
// domain assets — the honest way to feed the DNS and CT connectors a
// real target corpus without scanning anyone: the domains are the
// list's own publication (Majestic publishes the file for free
// download; each row is what the operator may legitimately point
// lookups at).
//
// Honesty contract (R39 P1):
//   - This is a SNAPSHOT source.  The file is a periodic aggregate;
//     GSEER records the fetch time as observed_at and the list's own
//     attribution in every evidence object.  No per-record timestamp
//     exists upstream — none is invented.
//   - Rank/RefSubNets/RefIPs are the LIST's published numbers, copied
//     verbatim into evidence — not re-measured claims.
//   - Ingestion is line-offset checkpointed (the same composite-cursor
//     pattern as the delegated connector): a run that hits its budget
//     resumes at the line offset; the header line is always consumed.
//
// Politeness: ONE request per run against a file the publisher
// distributes for that purpose; the shared client's rate limits and
// body caps apply (a dedicated long-window client like the delegated
// connector's, because the file is far larger than the JSON-grade
// cap).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// topdomainsDefaultEndpoint is Majestic's free download (the Majestic
// Million: the top million domains by referring subnets).  Operators
// can point the source at any compatible CSV (GlobalRank,...,Domain
// header) via the source endpoint.
const topdomainsDefaultEndpoint = "https://downloads.majestic.com/majestic_million.csv"

// topdomainsAttribution rides in every evidence object — the license
// story travels with the data (docs/SOURCES.md §H).
const topdomainsAttribution = "Majestic Million (majestic.com) — public domain-popularity list, free download; snapshot data, not a live observation"

type topdomainsConnector struct{}

func (topdomainsConnector) Kind() string { return "topdomains" }

func (topdomainsConnector) Review() Review {
	return Review{
		Verdict: ReviewEnabled,
		Why:     "the publisher distributes the file for free public download; ingestion records the list verbatim with attribution and fetch time, no redistribution requirement is imposed on the index",
		DocRef:  "docs/SOURCES.md §H (Majestic Million)",
	}
}

// topdomainsCursor is the checkpoint: the consumed line count (the
// header line counts) and the endpoint it belongs to.
type topdomainsCursor struct {
	Offset   int64  `json:"offset"`
	Endpoint string `json:"endpoint"`
}

func parseTopdomainsCursor(raw string) (topdomainsCursor, bool) {
	if strings.TrimSpace(raw) == "" {
		return topdomainsCursor{}, false
	}
	var c topdomainsCursor
	if json.Unmarshal([]byte(raw), &c) != nil {
		return topdomainsCursor{}, false
	}
	return c, true
}

func (topdomainsConnector) Collect(ctx Ctx) (*Batch, error) {
	if ctx.Client == nil {
		return nil, fmt.Errorf("topdomains: the run has no shared HTTP client")
	}
	endpoint := ctx.Config.Endpoint
	if endpoint == "" {
		endpoint = topdomainsDefaultEndpoint
	}
	limit := ctx.Limit
	if limit <= 0 {
		limit = delegatedDefaultLimit
	}
	cur, _ := parseTopdomainsCursor(ctx.Cursor)
	if cur.Endpoint != "" && cur.Endpoint != endpoint {
		// The operator changed the endpoint: restart the walk rather
		// than splice two files into one cursor.
		cur = topdomainsCursor{}
	}

	// The list is plain text far larger than the shared JSON-grade
	// body cap, so the fetch runs on a dedicated long-window client
	// (still rate-limited) — the delegated connector's pattern.
	fetch := NewClient(ClientConfig{
		RequestsPerSecond: 2,
		Timeout:           10 * time.Minute,
		MaxBodyBytes:      256 << 20,
	})
	body, err := fetch.Get(ctx.Context, endpoint)
	if err != nil {
		return nil, fmt.Errorf("topdomains: cannot fetch %s: %w", endpoint, err)
	}
	defer func() { _ = body.Close() }()

	facts, consumed, total, invalid, ferr := topdomainsParse(ctx.Context, body, cur.Offset, limit, ctx.Now())
	if ferr != nil {
		return nil, fmt.Errorf("topdomains: parse of %s failed: %w", endpoint, ferr)
	}

	out := topdomainsCursor{Offset: consumed, Endpoint: endpoint}
	done := total >= 0 // parse saw EOF: the file is fully consumed
	notes := map[string]int{
		"lines_consumed":  int(consumed),
		"lines_total":     total,
		"facts":           len(facts),
		"skipped:invalid": invalid,
	}
	batch := &Batch{
		Raws:   facts,
		Cursor: mustJSON(out),
		Done:   done,
		Notes:  notes,
	}
	return batch, nil
}

// topdomainsParse streams the CSV body from line `offset` (the header
// line is line 1 and is always re-skipped on resume; it is not part of
// a data offset).  It returns the facts, the consumed line offset
// AFTER the current batch, and the total line count when EOF was
// reached (-1 while truncated by the budget).  Lines that do not parse
// (short rows, non-numeric rank, header repeats, comment lines) are
// counted, never fabricated into facts.
func topdomainsParse(ctx context.Context, r io.Reader, offset int64, limit int, now time.Time) ([]RawFact, int64, int, int, error) {
	br := bufio.NewReader(io.LimitReader(r, 512<<20)) // hard cap: 512 MiB decompressed text
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	facts := make([]RawFact, 0, 512)
	var lineNo int64 // 1-based data-line number (after the header)
	invalid := 0
	headerSeen := false
	sawEOF := false
	total := -1

	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, 0, -1, invalid, ctx.Err()
		}
		rawLine := strings.TrimSpace(sc.Text())
		if rawLine == "" {
			continue
		}
		if !headerSeen {
			headerSeen = true
			continue // the header is structural; it is never a fact
		}
		lineNo++
		if lineNo <= offset {
			continue // resume skip: consumed by an earlier run
		}
		if len(facts) >= limit {
			// Budget exhausted: the next run resumes at this data-line
			// offset; EOF was not reached, so the total stays unknown.
			return facts, lineNo, -1, invalid, nil
		}
		f, ok := topdomainsRow(rawLine, now)
		if !ok {
			invalid++
			continue
		}
		facts = append(facts, f)
	}
	if err := sc.Err(); err != nil {
		return nil, 0, -1, invalid, err
	}
	sawEOF = true
	// EOF: lineNo counts every data line in the file (the resume skip
	// still counts them), so the file's data-line total is lineNo.
	if sawEOF {
		total = int(lineNo)
	}
	return facts, lineNo, total, invalid, nil
}

// topdomainsRow parses one CSV line (GlobalRank,TldRank,Domain,TLD,
// RefSubNets,RefIPs,...) into a domain asset fact.  ok=false for rows
// without a plausible rank+domain pair.
func topdomainsRow(line string, now time.Time) (RawFact, bool) {
	fields := strings.Split(line, ",")
	if len(fields) < 6 {
		return RawFact{}, false
	}
	rank, err := strconv.Atoi(strings.TrimSpace(fields[0]))
	if err != nil || rank <= 0 {
		return RawFact{}, false
	}
	domain := strings.ToLower(strings.TrimSpace(fields[2]))
	if domain == "" || !strings.Contains(domain, ".") {
		return RawFact{}, false
	}
	refnets, _ := strconv.Atoi(strings.TrimSpace(fields[4]))
	refips, _ := strconv.Atoi(strings.TrimSpace(fields[5]))
	return RawFact{
		AssetKind:  "domain",
		Value:      domain,
		ObservedAt: now,
		Confidence: "medium", // a published popularity list, not a direct observation
		Extra: map[string]any{
			"topdomains": map[string]any{
				"rank":        rank,
				"tld":         strings.ToLower(strings.TrimSpace(fields[3])),
				"refnets":     refnets,
				"refips":      refips,
				"attribution": topdomainsAttribution,
			},
		},
	}, true
}

func init() { register(topdomainsConnector{}) }
