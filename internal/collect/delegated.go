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

// delegated.go — the RIR delegated-statistics connector (R38 P1/P6):
// aggregated ALLOCATION data published by the five Regional Internet
// Registries as "delegated-extended" files (NRO coordination).
//
// WHAT IT DOES: fetches each RIR's latest delegated-extended file and
// records one fact per allocated prefix (IPv4 block or IPv6 prefix)
// with the allocation's registry, ISO country code, status and date —
// registry-level truth about WHO holds Internet space, DISTINCT from
// BGP origination (routeviews) and IP-to-ASN attribution (ip2asn).
// The country code enriches the asset (searchable `country == "ID"`).
//
// TERMS — reviewed-enabled.  The RIRs publish the delegated lists as
// public aggregated statistics for Internet research; the attribution
// below rides on EVERY fact.  Rows are already aggregated (no
// subscriber data); nothing is scanned — this is a file download.
//
// INCREMENTAL (R38): the composite checkpoint {"serials", "partial",
// "offset"} — an RIR whose file serial matches the checkpoint is
// skipped entirely; the RIR being consumed resumes at its line
// offset (lines are stable within one file version).  A new serial
// restarts that RIR's walk (freshness, error handling: the walk is
// re-driven by the next run).
//
// SCOPE (v1): ipv4 and ipv6 rows (registry truth about prefixes).
// ASN rows are deliberately not emitted — the asset model has no ASN
// assets; ASN intelligence comes from ip2asn/routeviews.  Non-CIDR-
// aligned ipv4 blocks (should not occur in extended files) are
// counted and skipped, never invented.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// delegatedAttribution — per-fact attribution (NRO/RIR public stats).
const delegatedAttribution = "RIR Delegated-Extended Statistics (NRO — public aggregated allocation data; https://www.nro.net/about/rirs/statistics/)"

// delegatedSources — the five RIRs' delegated-extended endpoints.
var delegatedSources = []string{
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

// delegatedDefaultLimit bounds one run's prefix facts.
const delegatedDefaultLimit = 30000

type delegatedConnector struct{}

func (delegatedConnector) Kind() string { return "delegated" }

func (delegatedConnector) Review() Review {
	return Review{
		Verdict: "reviewed-enabled",
		Why:     "RIR delegated-extended files are public aggregated allocation statistics (NRO coordination); attribution preserved on every fact; passive file download, no scanning",
		DocRef:  "docs/SOURCES.md §B",
	}
}

// delegatedCursor is the composite checkpoint (R38): the consumed
// file serials per registry, the registry partially consumed and the
// line offset within it.
type delegatedCursor struct {
	Serials map[string]string `json:"serials"`
	Partial string            `json:"partial"`
	Offset  int64             `json:"offset"`
}

func parseDelegatedCursor(raw string) (delegatedCursor, bool) {
	if strings.TrimSpace(raw) == "" {
		return delegatedCursor{}, false
	}
	var c delegatedCursor
	if json.Unmarshal([]byte(raw), &c) != nil {
		return delegatedCursor{}, false
	}
	if c.Serials == nil {
		c.Serials = map[string]string{}
	}
	return c, true
}

func (c delegatedConnector) Collect(ctx Ctx) (*Batch, error) {
	if ctx.Client == nil {
		return nil, fmt.Errorf("delegated: the run has no shared HTTP client")
	}
	limit := ctx.Limit
	if limit <= 0 {
		limit = delegatedDefaultLimit
	}
	cur, _ := parseDelegatedCursor(ctx.Cursor)

	notes := map[string]int{"records": 0, "facts": 0, "skipped:aligned": 0, "skipped:done": 0, "serials_done": 0}
	seenInRun := map[string]bool{}
	facts := make([]RawFact, 0, 512)
	out := &delegatedCursor{Serials: map[string]string{}}
	for k, v := range cur.Serials {
		out.Serials[k] = v
	}

	for _, endpoint := range delegatedSources {
		if len(facts) >= limit {
			break // the run's budget is gone; the next run resumes here
		}
		registry := delegatedRegistryOf(endpoint)
		if cur.Serials[registry] != "" && cur.Partial != registry {
			// The file was consumed in an earlier run; the NEXT run
			// still refreshes it (freshness contract), so a skip only
			// happens when this run already passed the registry in a
			// resumed walk — never across runs.
			if seenInRun[registry] {
				notes["skipped:done"]++
				continue
			}
		}
		resume := int64(0)
		if cur.Partial == registry {
			resume = cur.Offset
		}

		// The files are plain text but far larger than the shared
		// JSON-grade body cap, so the fetch runs on a dedicated
		// long-window client (still rate-limited).
		fetch := NewClient(ClientConfig{
			RequestsPerSecond: 2,
			Timeout:           10 * time.Minute,
			MaxBodyBytes:      256 << 20,
		})
		body, gerr := fetch.Get(ctx.Context, endpoint)
		if gerr != nil {
			return nil, fmt.Errorf("delegated: cannot fetch %s: %w", registry, gerr)
		}
		seenInRun[registry] = true
		rows, serial, offset, n, berr := delegatedParse(ctx.Context, body, registry, resume, limit-len(facts), ctx.Now())
		_ = body.Close()
		if berr != nil {
			return nil, fmt.Errorf("delegated: parse of %s failed: %w", registry, berr)
		}
		notes["records"] += n
		facts = append(facts, rows...)

		if len(facts) >= limit {
			// Partially consumed: the next run resumes at the line offset.
			out.Partial = registry
			out.Offset = offset
			break
		}
		// The file is fully consumed (parse hit EOF within budget):
		// record its serial so the freshness story is honest.
		if serial != "" {
			out.Serials[registry] = serial
			notes["serials_done"]++
		}
		out.Partial = ""
		out.Offset = 0
	}

	notes["facts"] = len(facts)
	batch := &Batch{
		Raws:   facts,
		Cursor: mustJSON(out),
		Done:   out.Partial == "",
		Notes:  notes,
	}
	return batch, nil
}

// delegatedRegistryOf names the RIR from its endpoint path.
func delegatedRegistryOf(endpoint string) string {
	for _, r := range []string{"arin", "ripencc", "apnic", "lacnic", "afrinic"} {
		if strings.Contains(endpoint, r) {
			return r
		}
	}
	return "unknown"
}

// delegatedParse streams one delegated-extended file, skips `skip`
// lines, and yields up to maxFacts prefix facts.  Returns the rows,
// the file's serial (from its version header), the new line offset
// and the rows seen.
func delegatedParse(ctx context.Context, r io.Reader, registry string, skip int64, maxFacts int, now time.Time) ([]RawFact, string, int64, int, error) {
	br := bufio.NewReader(io.LimitReader(r, 512<<20)) // hard cap: 512 MiB decompressed text
	var serial string
	var facts []RawFact
	var offset int64
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	line := int64(0)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return facts, serial, offset, int(offset), err
		}
		line++
		offset = line
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Split(text, "|")
		if len(f) < 7 {
			continue
		}
		if serial == "" && f[0] == "version" && len(f) >= 4 {
			serial = f[2] // version|registry|serial|records
			continue
		}
		if f[0] != registry { // data rows carry the registry name in col 0
			continue
		}
		typ := f[2]
		if typ != "ipv4" && typ != "ipv6" {
			continue // asn rows: see the connector's SCOPE note
		}
		cc := strings.ToLower(f[1])
		start, value, date, status := f[3], f[4], f[5], f[6]

		var prefix netip.Prefix
		if typ == "ipv4" {
			n, err := netip.ParseAddr(strings.TrimSpace(start))
			if err != nil {
				continue
			}
			count, err := strconv.ParseUint(value, 10, 32)
			if err != nil || count == 0 {
				continue
			}
			hostBits := 32 - bits.Len32(uint32(count))
			if uint64(1)<<uint(hostBits) != count {
				// A non-CIDR-aligned block: the extended format should
				// never emit one; count and skip (never invent).
				continue
			}
			prefix = netip.PrefixFrom(n.Unmap(), 32-int(hostBits)).Masked()
		} else {
			n, err := netip.ParseAddr(strings.TrimSpace(start))
			if err != nil {
				continue
			}
			plen, err := strconv.Atoi(value)
			if err != nil || plen < 0 || plen > 128 {
				continue
			}
			prefix = netip.PrefixFrom(n, plen).Masked()
		}
		if !prefix.IsValid() || !prefix.Addr().IsGlobalUnicast() {
			continue
		}

		facts = append(facts, RawFact{
			AssetKind:  "ip",
			Value:      prefix.Addr().String(),
			ObservedAt: now,
			Confidence: "high",
			GeoCountry: cc,
			Extra: map[string]any{
				"delegated": map[string]any{
					"attribution": delegatedAttribution,
					"registry":    registry,
					"country":     cc,
					"prefix":      prefix.String(),
					"status":      status,
					"allocated_at": func() string {
						if len(date) == 8 {
							if t, err := time.Parse("20060102", date); err == nil {
								return t.Format("2006-01-02")
							}
						}
						return date
					}(),
					"type": typ,
				},
			},
		})
		if len(facts) >= maxFacts {
			return facts, serial, offset, int(line), nil
		}
	}
	if err := sc.Err(); err != nil {
		return facts, serial, offset, int(line), err
	}
	return facts, serial, offset, int(line), nil
}

func init() { register(delegatedConnector{}) }
