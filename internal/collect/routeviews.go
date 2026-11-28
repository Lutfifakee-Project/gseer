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

// routeviews.go — the BGP/AS-coverage connector (R34), backed by the
// University of Oregon RouteViews Project's RIB archive dumps
// (provider identity, endpoints and terms: docs/SOURCES.md §B).
//
// WHAT IT DOES: lists the collector archive's newest RIB MRT dump
// (rib.YYYYMMDD.HHMM.bz2), streams it through the MRT TABLE_DUMP_V2
// parser, and records one prefix → origin-AS fact per announced prefix
// with ASN enrichment and full provenance (collector, file, peer,
// originated_at).  The facts are IP-ASSET facts keyed by the prefix's
// network address — the search surface answers "which AS originates
// this network" over real BGP data.
//
// TERMS — reviewed-enabled.  RouteViews publishes its data under CC
// BY 4.0; the attribution string below rides on EVERY fact (the
// license obligation is preserved verbatim, on the record).
//
// INCREMENTAL (R34/R35): the composite checkpoint {"file", "offset"}
// resumes a partially-consumed dump (decompressed byte offset; bz2
// cannot seek, so the resume re-streams and skips), and a new file
// resets it.  One run consumes at most LimitPerRun prefix facts.
//
// PLAUSIBILITY GATE (R34 integrity): only masked, global-unicast,
// length-bounded prefixes with an in-range origin ASN become facts —
// implausible parses are counted ("bad:<shape>") and skipped, never
// invented into attribution.

import (
	"bufio"
	"compress/bzip2"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// routeviewsAttribution — the CC BY 4.0 requirement, on every fact.
const routeviewsAttribution = "RouteViews Project, University of Oregon — CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)"

// routeviewsCollectorName — the RIB dumps are the default VRF view.
const routeviewsCollectorName = "VRF default"

// routeviewsMaxEntriesPerFile caps one file's prefix facts per run
// (the runner's LimitPerRun; 0 = default).
const routeviewsDefaultLimit = 30000

var (
	routeviewsMonthRe = regexp.MustCompile(`href="(\d{4}\.\d{2})/"`)
	routeviewsRIBRe   = regexp.MustCompile(`href="(rib\.\d{8}\.\d{4}\.bz2)"`)
)

type routeviewsConnector struct{}

func (routeviewsConnector) Kind() string { return "routeviews" }

func (routeviewsConnector) Review() Review {
	return Review{
		Verdict: "reviewed-enabled",
		Why:     "RouteViews publishes BGP RIB archives under CC BY 4.0 (attribution preserved on every fact); passive dataset, no scanning",
		DocRef:  "docs/SOURCES.md §I",
	}
}

// routeviewsCursor is the composite checkpoint (R34): the consumed
// dump and the decompressed byte offset into it.
type routeviewsCursor struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
	Facts  int64  `json:"facts"`
}

func parseRouteviewsCursor(raw string) (routeviewsCursor, bool) {
	if strings.TrimSpace(raw) == "" {
		return routeviewsCursor{}, false
	}
	var c routeviewsCursor
	if json.Unmarshal([]byte(raw), &c) != nil || c.File == "" {
		return routeviewsCursor{}, false
	}
	return c, true
}

func (c routeviewsConnector) Collect(ctx Ctx) (*Batch, error) {
	if ctx.Client == nil {
		return nil, fmt.Errorf("routeviews: the run has no shared HTTP client")
	}
	base := strings.TrimRight(ctx.Config.Endpoint, "/")
	if base == "" {
		return nil, fmt.Errorf("routeviews: the source config needs \"endpoint\" (the archive base, e.g. https://archive.routeviews.org/route-views2/bgpdata/)")
	}
	limit := ctx.Limit
	if limit <= 0 {
		limit = routeviewsDefaultLimit
	}
	now := ctx.Now

	// 1. The newest RIB dump in the archive (month dir → RIBS/ → file).
	fileURL, fileName, lerr := routeviewsNewestRIB(ctx.Context, ctx.Client, base)
	if lerr != nil {
		return nil, fmt.Errorf("routeviews: cannot resolve the newest RIB dump under %s: %w", base, lerr)
	}

	// 2. Resume state: same file → skip the consumed offset; a new
	// file restarts the walk (recovery from source resets is exactly
	// this path — the dump is re-streamed from its head).
	cur, _ := parseRouteviewsCursor(ctx.Cursor)
	resumeOffset := int64(0)
	if cur.File == fileName {
		resumeOffset = cur.Offset
	}

	// 3. Stream + decompress + parse (bz2 is sequential: the resume
	// offset re-streams from the head and skips — recovery is exactly
	// this path).  The dump is far larger than the shared client's
	// JSON-grade body cap, so the download runs on a dedicated
	// long-window client (still rate-limited; 1 GiB hard cap).
	dump := NewClient(ClientConfig{
		RequestsPerSecond: 2,
		Timeout:           15 * time.Minute,
		MaxBodyBytes:      1 << 30,
	})
	body, gerr := dump.Get(ctx.Context, fileURL)
	if gerr != nil {
		return nil, fmt.Errorf("routeviews: cannot stream %s: %w", fileURL, gerr)
	}
	defer func() { _ = body.Close() }()

	facts, offset, notes, berr := routeviewsParse(ctx.Context, bzip2.NewReader(body), resumeOffset, limit, fileName, now())
	if berr != nil && len(facts) == 0 {
		return nil, fmt.Errorf("routeviews: parse of %s failed: %w", fileName, berr)
	}

	batch := &Batch{
		Raws:   facts,
		Cursor: mustJSON(routeviewsCursor{File: fileName, Offset: offset, Facts: int64(len(facts))}),
		Done:   berr == nil, // a clean EOF means the dump is fully consumed
		Notes:  notes,
	}
	return batch, nil
}

// routeviewsNewestRIB resolves the newest rib.*.bz2 under the archive
// base (bgpdata/<YYYY.MM>/RIBS/rib.YYYYMMDD.HHMM.bz2).
func routeviewsNewestRIB(ctx context.Context, client *Client, base string) (string, string, error) {
	monthsSrc, err := client.Get(ctx, base+"/")
	if err != nil {
		return "", "", err
	}
	months := routeviewsMonthRe.FindAllStringSubmatch(readAll(monthsSrc), -1)
	_ = monthsSrc.Close()
	if len(months) == 0 {
		return "", "", fmt.Errorf("no month directories listed")
	}
	names := monthDirs(months)
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) > 3 {
		names = names[:3]
	}
	for _, month := range names { // walk the NEWEST months until a RIB is listed
		ribsSrc, rerr := client.Get(ctx, base+"/"+month+"/RIBS/")
		if rerr != nil {
			continue
		}
		ribs := routeviewsRIBRe.FindAllStringSubmatch(readAll(ribsSrc), -1)
		_ = ribsSrc.Close()
		if len(ribs) == 0 {
			continue
		}
		names := make([]string, 0, len(ribs))
		for _, r := range ribs {
			names = append(names, r[1])
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		name := names[0]
		return base + "/" + month + "/RIBS/" + name, name, nil
	}
	return "", "", fmt.Errorf("no RIB dumps listed under the newest months")
}

func monthDirs(ms [][]string) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m[1]
	}
	return out
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4<<20))
	return string(b)
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// routeviewsParse streams one MRT TABLE_DUMP_V2 RIB dump, skips
// `skip` decompressed bytes (the resume offset), and yields up to
// maxFacts prefix facts.  Returns the facts, the new decompressed
// offset and the run notes.
func routeviewsParse(ctx context.Context, r io.Reader, skip int64, maxFacts int, file string, now time.Time) ([]RawFact, int64, map[string]int, error) {
	notes := map[string]int{"records": 0, "facts": 0, "bad:shape": 0, "skipped_implausible": 0}
	br := bufio.NewReader(io.LimitReader(r, 4<<30)) // hard cap: 4 GiB decompressed
	// Honesty gate: the stream must actually be bzip2 (the archive
	// answers rate-limit/error pages with HTML; parsing those as MRT
	// would manufacture garbage instead of reporting the refusal).
	if magic, _ := br.Peek(3); string(magic) != "BZh" {
		return nil, 0, notes, fmt.Errorf("the archive body is not a bzip2 stream (magic %q) — rate limit or error page; retry later", magic)
	}
	if skip > 0 {
		if _, err := io.CopyN(io.Discard, br, skip); err != nil {
			return nil, skip, notes, nil // the dump changed under us; restart next run
		}
	}

	facts := make([]RawFact, 0, 1024)
	seen := map[string]bool{}
	var offset int64
	hdr := make([]byte, 12)

	readFull := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		offset += int64(n)
		return buf, nil
	}

	peers := map[uint16]string{} // peer index → identity (IP address)

	for len(facts) < maxFacts {
		if err := ctx.Err(); err != nil {
			return facts, offset, notes, err
		}
		if _, err := io.ReadFull(br, hdr); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return facts, offset, notes, nil // clean EOF: dump consumed
			}
			return facts, offset, notes, err
		}
		ts := binary.BigEndian.Uint32(hdr[0:4])
		mrtType := binary.BigEndian.Uint16(hdr[4:6])
		subtype := binary.BigEndian.Uint16(hdr[6:8])
		length := binary.BigEndian.Uint32(hdr[8:12])
		if length > 64<<20 {
			return facts, offset, notes, fmt.Errorf("implausible MRT record length %d at offset %d", length, offset)
		}
		body, err := readFull(int(length))
		if err != nil {
			return facts, offset, notes, err
		}
		if mrtType != 13 { // TABLE_DUMP_V2 only
			continue
		}
		notes["records"]++

		switch subtype {
		case 1: // PEER_INDEX_TABLE
			if len(body) < 6 {
				notes["bad:shape"]++
				continue
			}
			p := 6 // bgp_id(4) + view_len(2) — view name skipped by offset below
			viewLen := int(binary.BigEndian.Uint16(body[4:6]))
			p += viewLen
			// entry count then fixed-width entries per their type byte
			if p >= len(body) {
				notes["bad:shape"]++
				continue
			}
			if p+2 > len(body) {
				notes["bad:shape"]++
				break
			}
			count := int(binary.BigEndian.Uint16(body[p : p+2]))
			p += 2
			for i := 0; i < count && p < len(body); i++ {
				typ := body[p]
				p++
				ipLen := 4
				if typ&0x02 != 0 { // IPv6 bit
					ipLen = 16
				}
				if p+ipLen > len(body) {
					notes["bad:shape"]++
					break
				}
				ip := net.IP(body[p : p+ipLen])
				p += ipLen
				asnLen := 2
				if typ&0x01 != 0 { // 4-byte ASN bit
					asnLen = 4
				}
				p += asnLen
				peers[uint16(i)] = ip.String()
			}
		case 2, 4: // RIB_IPV4_UNICAST / RIB_IPV6_UNICAST
			fact, ok := routeviewsRIBEntry(body, subtype == 4, peers, file, ts, now, notes)
			if !ok {
				continue
			}
			if seen[fact.Value] {
				continue // one fact per prefix per run (first entry wins)
			}
			seen[fact.Value] = true
			facts = append(facts, fact)
		default:
			// 3/5 multicast, BGP4MP, etc. — not part of the unicast story.
		}
	}
	notes["facts"] = len(facts)
	return facts, offset, notes, nil
}

// routeviewsRIBEntry decodes one RIB unicast record body into a raw
// fact (the first path entry's origin AS + peer).  ok=false for
// implausible/shape-broken records (counted, never fatal).
func routeviewsRIBEntry(body []byte, v6 bool, peers map[uint16]string, file string, ts uint32, now time.Time, notes map[string]int) (RawFact, bool) {
	// Live-verified layout (rib.20261125.1400.bz2): the RIB record body
	// opens with a 4-byte SEQUENCE, then prefix length, the unpadded
	// prefix, the 2-byte entry count and the entries.
	if len(body) < 8 {
		notes["bad:shape"]++
		return RawFact{}, false
	}
	pLen := int(body[4])
	maxLen := 32
	if v6 {
		maxLen = 128
	}
	if pLen < 0 || pLen > maxLen {
		notes["skipped_implausible"]++
		return RawFact{}, false
	}
	pfxBytes := (pLen + 7) / 8
	if 5+pfxBytes+2 > len(body) {
		notes["bad:shape"]++
		return RawFact{}, false
	}
	var addrBytes [16]byte
	copy(addrBytes[:], body[5:5+pfxBytes])
	var addr netip.Addr
	if v6 {
		addr = netip.AddrFrom16(addrBytes)
	} else {
		addr = netip.AddrFrom4([4]byte(addrBytes[:4]))
	}
	prefix := netip.PrefixFrom(addr, pLen).Masked()
	if !prefix.Addr().IsGlobalUnicast() {
		notes["skipped_implausible"]++
		return RawFact{}, false
	}

	entries := int(binary.BigEndian.Uint16(body[5+pfxBytes : 7+pfxBytes]))
	p := 7 + pfxBytes
	for i := 0; i < entries && p+8 <= len(body); i++ {
		peerIdx := binary.BigEndian.Uint16(body[p : p+2])
		originated := time.Unix(int64(binary.BigEndian.Uint32(body[p+2:p+6])), 0).UTC()
		attrLen := int(binary.BigEndian.Uint16(body[p+6 : p+8]))
		p += 8
		if p+attrLen > len(body) {
			notes["bad:shape"]++
			break
		}
		attrs := body[p : p+attrLen]
		p += attrLen

		origin := routeviewsOriginASN(attrs)
		if origin <= 0 || origin > 4294967295 {
			continue // no usable AS_PATH in this entry
		}
		peer, ok := peers[peerIdx]
		if !ok {
			peer = fmt.Sprintf("peer-%d", peerIdx)
		}
		return RawFact{
			AssetKind:  "ip",
			Value:      prefix.Addr().String(),
			ObservedAt: now,
			Confidence: "medium",
			ASN:        int(origin),
			Extra: map[string]any{
				"routeviews": map[string]any{
					"attribution": routeviewsAttribution,
					"collector":   routeviewsCollectorName,
					"file":        file,
					"origin_asn":  origin,
					"originated_at": func() string {
						if ts > 0 {
							return originated.Format(time.RFC3339)
						}
						return originated.Format(time.RFC3339)
					}(),
					"peer":   peer,
					"prefix": prefix.String(),
				},
			},
		}, true
	}
	return RawFact{}, false
}

// routeviewsOriginASN extracts the origin AS from the path attributes:
// the LAST ASN of the AS_PATH (attribute type 2), preferring AS4
// encoding when present (attribute type 17).
func routeviewsOriginASN(attrs []byte) int64 {
	best := int64(0)
	p := 0
	for p+2 <= len(attrs) {
		flags := attrs[p]
		typ := attrs[p+1]
		var l int
		if flags&0x10 != 0 { // extended length
			if p+4 > len(attrs) {
				break
			}
			l = int(binary.BigEndian.Uint16(attrs[p+2 : p+4]))
			p += 4
		} else {
			if p+3 > len(attrs) {
				break
			}
			l = int(attrs[p+2])
			p += 3
		}
		if p+l > len(attrs) {
			break
		}
		if typ == 2 || typ == 17 { // AS_PATH / AS4_PATH
			if asn := routeviewsPathLastASN(attrs[p:p+l], typ == 17); asn > 0 {
				best = asn // the LAST AS_PATH attribute wins (AS4 over 2-byte)
			}
		}
		p += l
	}
	return best
}

// routeviewsPathLastASN walks the AS_PATH segments and returns the
// final ASN (wide ASN bytes when as4).
func routeviewsPathLastASN(b []byte, as4 bool) int64 {
	last := int64(0)
	p := 0
	for p+2 <= len(b) {
		segType := b[p]
		count := int(b[p+1])
		p += 2
		width := 2
		if as4 {
			width = 4
		}
		if p+count*width > len(b) {
			break
		}
		if count > 0 && (segType == 1 || segType == 2) { // AS_SET / AS_SEQUENCE
			off := p + (count-1)*width
			if as4 {
				last = int64(binary.BigEndian.Uint32(b[off : off+4]))
			} else {
				last = int64(binary.BigEndian.Uint16(b[off : off+2]))
			}
		}
		p += count * width
	}
	return last
}

func init() { register(routeviewsConnector{}) }
