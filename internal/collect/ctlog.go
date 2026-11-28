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

// ctlog.go — the SEED-FREE Certificate Transparency log connector
// (v0.3.2 Rev 14; provider, endpoint and terms: docs/SOURCES.md §G).
//
// Unlike the disabled crt.sh aggregation connector (`ct`, §A — per-seed
// identity queries, unclear provider terms), this connector speaks the
// RFC 6962/9162 protocol DIRECTLY to a public CT log: get-sth + get-entries
// are public audit APIs that the standard requires every log to serve
// (RFC 9162 §5), the certificates themselves are public artifacts (they
// travel inside every TLS handshake), and the log endpoints come from the
// official public log list.  No operator seeds are involved at all: each
// run reads a bounded window of the log's FRESHEST entries and discovers
// every DNS name the contained certificates cover.
//
// WHAT IT DOES: read-only HTTPS GETs to the LOG ONLY — GSEER never
// contacts a discovered domain because of a CT sighting (discovery ≠
// observation; port/service facts stay reserved to explicit, scoped
// `gseer scan` runs).  One batch per run: tip-following start index,
// limit_per_run entries max, one request per chunk (default 128 entries,
// RFC 6962 caps a get-entries answer at 1000), rate-limited by the shared
// client.  Growth across runs: the checkpoint stores the last consumed
// index; the next run starts at max(cursor+1, tip-limit) so consecutive
// runs never gap and rarely overlap — overlaps re-read identical indices
// and dedupe at L1 (same delivery cursor), never double-counting a cert.
//
// Every fact carries full provenance: the log URL, the absolute entry
// index, the SHA-256 of the raw log leaf (the cryptographic evidence),
// the cert's issuer and validity window, and the CT log's own timestamp.
// observed_at is the honest fetch time; the cert timeline lives in the
// evidence payload.

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ctlogDefaultEndpoint is the log GSEER reads by default: Cloudflare's
// Nimbus 2026 log, taken from the official public log list
// (https://www.gstatic.com/ct/log_list/v3/log_list.json).  Operators can
// point `gseer source add --endpoint` at any log in that list.
const ctlogDefaultEndpoint = "https://ct.cloudflare.com/logs/nimbus2026/"

// ctlogPoliteness bounds one run's read volume (docs/SOURCES.md §G).
const (
	// ctlogDefaultChunk is the entries-per-request default (one HTTPS
	// GET per chunk; well under the RFC 6962 get-entries cap of 1000).
	ctlogDefaultChunk = 128
	// ctlogMaxChunk refuses operator configs large enough to stress the
	// log (a single get-entries answer must stay small).
	ctlogMaxChunk = 1000
	// RFC 6962 LogLeaf constants — entry_type is a TLS uint16.
	ctlogLeafVersionV1 byte   = 0
	ctlogEntryX509     uint16 = 0x0000
	ctlogEntryPrecert  uint16 = 0x0001
)

// ctlogConnector implements the seed-free CT log discovery connector.
type ctlogConnector struct{}

// Kind implements Collector.
func (ctlogConnector) Kind() string { return "ctlog" }

// Review implements Collector (docs/SOURCES.md §G — verdict: ENABLED).
// The basis is the protocol, not a provider's licence page: RFC 9162
// requires logs to serve get-entries/get-sth to the public, the log list
// is a published public directory, certificates are public data, and the
// connector reads bounded, read-only windows from the log endpoint only.
func (ctlogConnector) Review() Review {
	return Review{
		Verdict: ReviewEnabled,
		Why:     "public audit infrastructure: RFC 9162 mandates the get-entries/get-sth APIs, log endpoints come from the official public log list, certificates are public data, reads are bounded and read-only against the log itself (never the discovered domains)",
		DocRef:  "docs/SOURCES.md §G (CT log walking)",
	}
}

// ctlogGetEntriesResponse is the RFC 6962 JSON get-entries answer.
type ctlogGetEntriesResponse struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	} `json:"entries"`
}

// ctlogSTH is the RFC 6962 JSON get-sth (signed tree head) answer.
type ctlogSTH struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp int64  `json:"timestamp"`
}

// Collect implements Collector: one tip-following, budget-bounded pass
// over a public CT log.  No seeds — seed_mode must be "none".
func (ctlogConnector) Collect(ctx Ctx) (*Batch, error) {
	if ctx.Client == nil {
		return nil, Fatal(fmt.Errorf("ctlog: no HTTP client configured — register the source with --requests-per-second (docs/SOURCES.md §G)"))
	}
	switch ctx.Config.SeedMode {
	case "", "none":
		// The only honest mode: nothing about this connector reads the
		// operator's or anyone's seed list.
	default:
		return nil, Fatal(fmt.Errorf("ctlog: seed_mode %q is not supported — this connector is seed-free; register it with --seed-mode none", ctx.Config.SeedMode))
	}

	endpoint := ctx.Config.Endpoint
	if endpoint == "" {
		endpoint = ctlogDefaultEndpoint
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	chunk := ctx.Config.Chunk
	if chunk <= 0 {
		chunk = ctlogDefaultChunk
	}
	if chunk > ctlogMaxChunk {
		chunk = ctlogMaxChunk
	}
	budget := ctx.Limit
	if budget <= 0 {
		budget = DefaultRunLimit
	}

	// Start index: resume from the checkpoint, else the configured
	// absolute index, else tip-following (the freshest window).
	now := time.Now().UTC()
	if ctx.Now != nil {
		now = ctx.Now().UTC()
	}
	var start uint64
	if cur, perr := strconv.ParseUint(strings.TrimSpace(ctx.Cursor), 10, 64); perr == nil && cur > 0 {
		start = cur + 1 // the checkpoint stores the LAST consumed index
	} else if ctx.Config.StartIndex > 0 {
		start = ctx.Config.StartIndex
	} else {
		var sth ctlogSTH
		if err := ctx.Client.GetJSON(ctx.Context, endpoint+"ct/v1/get-sth", &sth); err != nil {
			return nil, Fatal(fmt.Errorf("ctlog: get-sth failed for %s: %v (tip mode needs the tree size)", endpoint, err))
		}
		if sth.TreeSize == 0 {
			return nil, Fatal(fmt.Errorf("ctlog: %s reports an empty tree (tree_size 0)", endpoint))
		}
		start = ctlogTipStart(sth.TreeSize, uint64(budget))
	}

	raws := make([]RawFact, 0, 16)
	var (
		fetched, certs, precerts, nonLeaf, names int
		leafErrs                                 []error
		last                                     = start
	)
	for fetched < budget {
		if err := ctx.Context.Err(); err != nil {
			return nil, err
		}
		n := int64(chunk)
		if rem := int64(budget) - int64(fetched); rem < n {
			n = rem
		}
		end := last + uint64(n) - 1
		url := fmt.Sprintf("%sct/v1/get-entries?start=%d&end=%d", endpoint, last, end)
		var resp ctlogGetEntriesResponse
		if err := ctx.Client.GetJSON(ctx.Context, url, &resp); err != nil {
			if len(raws) > 0 {
				// A mid-run transport failure after successful batches
				// still delivers what was read (the checkpoint advances
				// only past ingested records; a retry resumes cleanly).
				break
			}
			return nil, err
		}
		if len(resp.Entries) == 0 {
			break // the log answered with nothing left at this index
		}
		for i, e := range resp.Entries {
			idx := last + uint64(i)
			leafDER, err := base64.StdEncoding.DecodeString(e.LeafInput)
			if err != nil {
				leafErrs = append(leafErrs, fmt.Errorf("entry %d: leaf_input does not decode", idx))
				continue
			}
			leafHash := sha256.Sum256(leafDER)
			info, perr := ctlogParseLeaf(leafDER)
			if perr != nil {
				nonLeaf++
				if _, isSkip := perr.(ctlogSkipLeaf); !isSkip {
					leafErrs = append(leafErrs, fmt.Errorf("entry %d: %v", idx, perr))
				}
				continue
			}
			if info.precert {
				precerts++
			} else {
				certs++
			}
			seenRaw := map[string]bool{}
			for _, raw := range info.names {
				// A wildcard SAN "*.foo.com" sightings the base name
				// foo.com (the certificate literally names it); the
				// canonicalization itself stays with the fact pipeline.
				raw = strings.TrimPrefix(strings.TrimSpace(raw), "*.")
				if raw == "" || seenRaw[strings.ToLower(raw)] {
					continue
				}
				seenRaw[strings.ToLower(raw)] = true
				names++
				extra := map[string]any{"ctlog": map[string]any{
					"log":            endpoint,
					"index":          idx,
					"leaf_sha256":    hex.EncodeToString(leafHash[:]),
					"cert_timestamp": info.timestampUTC.Format(time.RFC3339),
					"entry_type":     "precert",
				}}
				if info.precert {
					extra["ctlog"].(map[string]any)["entry_type"] = "precert"
				} else {
					extra["ctlog"].(map[string]any)["entry_type"] = "x509"
					if !info.notBefore.IsZero() {
						extra["ctlog"].(map[string]any)["not_before"] = info.notBefore.Format(time.RFC3339)
						extra["ctlog"].(map[string]any)["not_after"] = info.notAfter.Format(time.RFC3339)
					}
					if info.issuer != "" {
						extra["ctlog"].(map[string]any)["issuer"] = info.issuer
					}
					if info.subjectCN != "" {
						extra["ctlog"].(map[string]any)["subject_cn"] = info.subjectCN
					}
				}
				raws = append(raws, RawFact{
					AssetKind:  "hostname",
					Value:      raw,
					ObservedAt: now,
					Confidence: "high", // names come from cryptographically logged certificates
					Extra:      extra,
				})
			}
		}
		fetched += len(resp.Entries)
		last += uint64(len(resp.Entries))
		if len(resp.Entries) < int(n) {
			break // short answer: the log has nothing further at this index
		}
	}

	batch := &Batch{
		Raws: raws,
		Done: true, // one bounded batch per run; the next run resumes at the checkpoint
		Notes: map[string]int{"entries": fetched, "certs": certs, "precerts": precerts,
			"non_leaf": nonLeaf, "names": names, "requests": (int(fetched) + chunk - 1) / chunk},
	}
	// The checkpoint stores the LAST consumed absolute index ("": none).
	// A zero-work run (nothing new at the resume index) must KEEP the
	// existing checkpoint — echoing ctx.Cursor — instead of wiping the
	// resume point (caught by the runner-level regression test).
	switch {
	case fetched > 0:
		batch.Cursor = strconv.FormatUint(last-1, 10)
	case strings.TrimSpace(ctx.Cursor) != "":
		batch.Cursor = strings.TrimSpace(ctx.Cursor)
	}
	if len(leafErrs) > 0 {
		// Unreadable entries are recorded in the batch notes story and
		// surface via the run stats; the healthy majority still lands.
		batch.Notes["leaf_errors"] = len(leafErrs)
	}
	return batch, nil
}

// ctlogTipStart picks the freshest window start for a tree of the given
// size (never before the first entry).
func ctlogTipStart(treeSize, budget uint64) uint64 {
	if treeSize > budget {
		return treeSize - budget
	}
	return 0
}

// ctlogLeafInfo is the parsed subset of one log leaf.
type ctlogLeafInfo struct {
	timestampUTC time.Time
	notBefore    time.Time
	notAfter     time.Time
	issuer       string
	subjectCN    string // certificate Subject CommonName (x509 entries)
	names        []string
	precert      bool // pre-certificate entry (TBS SANs, no outer cert)
}

// ctlogSkipLeaf marks a leaf the connector deliberately does not parse
// (RFC 9162 v2 leaves) — skipped honestly, not an error.  Pre-certs are
// PARSED (they carry the freshest names); only v2 leaves are skipped.
type ctlogSkipLeaf struct{ why string }

func (e ctlogSkipLeaf) Error() string { return e.why }

// ctlogParseLeaf parses one RFC 6962 v1 MerkleTreeLeaf in the TLS
// presentation the JSON API actually serves (verified byte-for-byte
// against a live log — the entry_type discriminator is a TLS uint16):
//
//	version(1) || signature_type(1) || timestamp(8) || entry_type(2) || entry
//
// BOTH entry types yield facts.  x509_entry (0x0000): a 3-byte-length-
// prefixed DER certificate follows.  pre-cert_entry (0x0001):
// issuer_key_hash(32) + a 3-byte-length-prefixed TBSCertificate — the
// pre-cert's TBS carries the SAME SAN extension the final cert will ship,
// and the FRESHEST window of a public log is dominated by pre-certs
// (they are logged BEFORE the final certificate exists), so skipping them
// would gut seed-free discovery (the live E2E proved exactly that).
// Names are extracted from the TBS extensions (SAN OID 2.5.29.17,
// dNSName = context tag 2).
func ctlogParseLeaf(leaf []byte) (*ctlogLeafInfo, error) {
	if len(leaf) < 12 {
		return nil, fmt.Errorf("leaf too short (%d bytes)", len(leaf))
	}
	if leaf[0] != ctlogLeafVersionV1 {
		return nil, ctlogSkipLeaf{why: fmt.Sprintf("leaf version %d is not v1", leaf[0])}
	}
	ts := binary.BigEndian.Uint64(leaf[2:10])
	entryType := binary.BigEndian.Uint16(leaf[10:12])
	info := &ctlogLeafInfo{
		timestampUTC: time.UnixMilli(int64(ts)).UTC(),
	}
	if entryType == ctlogEntryX509 {
		// x509_entry: 3-byte length || DER certificate.
		if len(leaf) < 15 {
			return nil, fmt.Errorf("x509 entry truncated before length")
		}
		derLen := int(leaf[12])<<16 | int(leaf[13])<<8 | int(leaf[14])
		if derLen <= 0 || 15+derLen > len(leaf) {
			return nil, fmt.Errorf("x509 length %d out of bounds (leaf %d bytes)", derLen, len(leaf))
		}
		cert, err := x509.ParseCertificate(leaf[15 : 15+derLen])
		if err != nil {
			return nil, fmt.Errorf("certificate does not parse: %v", err)
		}
		info.notBefore = cert.NotBefore.UTC()
		info.notAfter = cert.NotAfter.UTC()
		info.issuer = cert.Issuer.CommonName
		info.subjectCN = cert.Subject.CommonName
		info.names = append([]string{}, cert.DNSNames...)
		if len(info.names) == 0 && cert.Subject.CommonName != "" {
			info.names = []string{cert.Subject.CommonName}
		}
		return info, nil
	}
	// Pre-certificate: issuer_key_hash(32) || 3-byte length || TBSCertificate
	// (after the 2-byte entry_type at bytes 10..11).
	if len(leaf) < 47 {
		return nil, fmt.Errorf("precert entry truncated")
	}
	tbsLen := int(leaf[44])<<16 | int(leaf[45])<<8 | int(leaf[46])
	if tbsLen <= 0 || 47+tbsLen > len(leaf) {
		return nil, fmt.Errorf("precert TBS length %d out of bounds (leaf %d bytes)", tbsLen, len(leaf))
	}
	names, err := ctlogTBSSANs(leaf[47 : 47+tbsLen])
	if err != nil {
		return nil, err
	}
	info.precert = true
	info.names = names
	return info, nil
}

// ctlogTBSSANs extracts the dNSName SAN entries (and the subject CN as a
// fallback) from one TBSCertificate DER.  Only what the certificate
// itself declares is read — nothing is inferred beyond the SAN extension.
func ctlogTBSSANs(tbs []byte) ([]string, error) {
	var parsed struct {
		Version  int `asn1:"optional,explicit,default:0,tag:0"`
		Serial   asn1.RawValue
		SigAlg   asn1.RawValue
		Issuer   asn1.RawValue
		Validity asn1.RawValue
		Subject  asn1.RawValue
		SPKI     asn1.RawValue
		Unique1  asn1.RawValue    `asn1:"optional,explicit,tag:1"`
		Unique2  asn1.RawValue    `asn1:"optional,explicit,tag:2"`
		Ext      []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	if _, err := asn1.Unmarshal(tbs, &parsed); err != nil {
		return nil, fmt.Errorf("TBSCertificate does not parse: %v", err)
	}
	var out []string
	for _, ext := range parsed.Ext {
		if !ext.Id.Equal(ctlogOIDSubjectAltName) {
			continue
		}
		out = append(out, ctlogDNSNamesFromSAN(ext.Value)...)
	}
	if len(out) == 0 {
		// Honest fallback: a common-name-only TBS still sightings its CN.
		var cn struct {
			Values []struct {
				OID  asn1.ObjectIdentifier
				Name string `asn1:"optional,utf8"`
			}
		}
		if _, err := asn1.Unmarshal(parsed.Subject.FullBytes, &cn); err == nil {
			for _, v := range cn.Values {
				if v.OID.Equal(ctlogOIDCommonName) && v.Name != "" {
					out = []string{v.Name}
					break
				}
			}
		}
	}
	return out, nil
}

// ctlogDNSNamesFromSAN walks the SAN extension value (SEQUENCE OF
// GeneralName) with a minimal TLV iterator and takes ONLY the dNSName
// entries ([2] IMPLICIT IA5String — context-specific class 2, primitive,
// tag number 2 = single byte 0x82).  A hand-rolled walk beats a
// reflect-based struct here: GeneralName is a CHOICE of mixed tags that
// encoding/asn1 models awkwardly, and the walk makes the "take exactly
// what the certificate declares" rule explicit.
func ctlogDNSNamesFromSAN(value []byte) []string {
	var names []string
	// unwrap the outer SEQUENCE header; the GeneralName elements live in
	// its CONTENT
	_, content, _, ok := ctlogTLV(value, 0)
	if !ok {
		return nil
	}
	for pos := 0; pos < len(content); {
		tag, inner, nx, ok := ctlogTLV(content, pos)
		if !ok {
			return names // trailing garbage: keep what we already read
		}
		if tag == 0x82 { // [2] IMPLICIT IA5String (dNSName)
			names = append(names, string(inner))
		}
		pos = nx
	}
	return names
}

// ctlogTLV parses one DER TLV at off: returns the identifier octet, the
// content bytes, the offset AFTER the TLV, and whether it fit in b.
func ctlogTLV(b []byte, off int) (byte, []byte, int, bool) {
	if off >= len(b) {
		return 0, nil, off, false
	}
	tag := b[off]
	p := off + 1
	if p >= len(b) {
		return 0, nil, off, false
	}
	l := int(b[p])
	p++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || p+n > len(b) {
			return 0, nil, off, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += n
	}
	if p+l > len(b) {
		return 0, nil, off, false
	}
	return tag, b[p : p+l], p + l, true
}

// SAN (2.5.29.17) and commonName (2.5.4.3) — read-only extraction, the
// same OIDs crypto/x509 uses.
var (
	ctlogOIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	ctlogOIDCommonName     = asn1.ObjectIdentifier{2, 5, 4, 3}
)

func init() { register(ctlogConnector{}) }
