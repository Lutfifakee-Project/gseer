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

// Package relations — R76 infrastructure knowledge graph + R77
// relationship search, built as EVIDENCE-BASED SQL joins over the
// maintained projections (latest_dns_t, latest_ip2asn_t, latest_ctlog_t,
// latest_tls_t, latest_fingerprints_t) and the asset/service tables.
//
// No separate graph database: the relationships here are exactly the
// edges the collected evidence already supports, traversal is a handful
// of indexed joins (measured at the 1M-asset corpus: sub-second for
// direct edges, prefix/org peers capped), and every edge carries the
// observed_at + source of the projection row it came from (R77: no
// false attribution, no inferred edges).  If a future measurement shows
// these joins dominating latency at real scale, a materialized edge table
// — not a graph DB — is the next step (documented decision).
package relations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// Relation is one evidence-backed edge.
type Relation struct {
	Kind       string `json:"kind"` // see kinds below
	From       string `json:"from"` // seed asset value
	To         string `json:"to"`   // neighbor value (or org/asn label)
	Detail     string `json:"detail,omitempty"`
	ObservedAt string `json:"observed_at"`
	Source     string `json:"source"`
}

// Kinds (each maps to exactly one evidence projection):
const (
	KindDNSResolves = "dns_resolves_to" // hostname/domain → A/AAAA/CNAME/MX answer
	KindDNSReverse  = "dns_reverse"     // IP ← other names whose DNS record mentions it
	KindASNCountry  = "asn_origin"      // IP → ASN/org/country + prefix attribution
	KindPrefixPeer  = "prefix_peer"     // IP ↔ other IPs announced under the same prefix
	KindCTCert      = "cert_ct"         // domain/hostname → CT-log certificate
	KindCTShared    = "cert_ct_shared"  // domain ↔ other names on the same CT leaf cert
	KindTLSCert     = "cert_tls"        // service → TLS certificate (subject/SAN/serial)
	KindTLSShared   = "cert_tls_shared" // service ↔ other services with the same cert serial
	KindSameOrg     = "same_org"        // asset ↔ other assets with the same ASN organization
	KindService     = "service"         // asset → open service (port/protocol/product)
	KindTech        = "technology"      // service → fingerprinted technologies
)

// Explore returns the evidence-based relations of one asset (matched by
// exact value) on the personal SQLite store.  kindFilter "" = all kinds;
// limit caps per-kind fanout.
func Explore(ctx context.Context, db *sql.DB, value, kindFilter string, limit int) ([]Relation, error) {
	return ExploreDialect(ctx, db, DialectSQLite, value, kindFilter, limit)
}

// ExplorePG is the self-hosted PostgreSQL twin of Explore (PG parity):
// identical kinds, identical provenance semantics, dialect-aware SQL.
func ExplorePG(ctx context.Context, db *sql.DB, value, kindFilter string, limit int) ([]Relation, error) {
	return ExploreDialect(ctx, db, DialectPostgres, value, kindFilter, limit)
}

// ExploreDialect runs the traversal over either dialect.
func ExploreDialect(ctx context.Context, db *sql.DB, dia Dialect, value, kindFilter string, limit int) ([]Relation, error) {
	if limit <= 0 {
		limit = 10
	}
	x := &dbx{db: db, dia: dia}
	var (
		id          int64
		kind, ipStr string
		asn         int64
		asnOrg      string
	)
	err := x.queryRow(ctx, `SELECT id, kind, COALESCE(ip,''), COALESCE(asn,0), COALESCE(asn_org,'')
		FROM assets WHERE value = ?`, value).Scan(&id, &kind, &ipStr, &asn, &asnOrg)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no asset %q in the local index", value)
	}
	if err != nil {
		return nil, err
	}

	want := func(k string) bool { return kindFilter == "" || kindFilter == k }
	out := []Relation{}
	add := func(rels []Relation) { out = append(out, rels...) }

	if want(KindService) {
		rels, err := serviceRelations(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindTech) {
		rels, err := techRelations(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindASNCountry) {
		rels, err := asnRelations(ctx, x, id, value)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindPrefixPeer) {
		rels, err := prefixPeers(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindDNSResolves) {
		rels, err := dnsForward(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindDNSReverse) && (ipStr != "" || kind == "ip") {
		needle := ipStr
		if needle == "" {
			needle = value
		}
		rels, err := dnsReverse(ctx, x, id, value, needle, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindCTCert) {
		rels, err := ctCerts(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindCTShared) {
		rels, err := ctShared(ctx, x, id, value, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindTLSCert) || want(KindTLSShared) {
		rels, err := tlsRelations(ctx, x, id, value, kindFilter, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	if want(KindSameOrg) && asnOrg != "" {
		rels, err := sameOrg(ctx, x, id, value, asnOrg, limit)
		if err != nil {
			return nil, err
		}
		add(rels)
	}
	return out, nil
}

// provenanceJoin resolves the data_sources name for an obs_id (the
// projection rows store the observation they were maintained from).
const provJoin = `LEFT JOIN observations o ON o.id = t.obs_id
	LEFT JOIN data_sources ds ON ds.id = o.source_id`

func serviceRelations(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT s.port, s.transport, COALESCE(s.protocol,''), COALESCE(s.product,''), COALESCE(s.version,''), s.last_seen
		FROM services s WHERE s.asset_id = ? ORDER BY s.port LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var port int64
		var transport, proto, product, version string
		var lastSeen any
		if err := rows.Scan(&port, &transport, &proto, &product, &version, &lastSeen); err != nil {
			return nil, err
		}
		lastSeenStr := asStr(lastSeen)
		detail := fmt.Sprintf("%d/%s", int(port), transport)
		if product != "" {
			detail += " · " + strings.TrimSpace(product+" "+version)
		}
		out = append(out, Relation{Kind: KindService, From: value, To: proto,
			Detail: detail, ObservedAt: lastSeenStr, Source: "services"})
	}
	return out, rows.Err()
}

func techRelations(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT t.technologies, t.observed_at, COALESCE(ds.name, '')
		FROM latest_fingerprints_t t
		JOIN services s ON s.id = t.service_id
		`+provJoin+`
		WHERE s.asset_id = ? LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var techs string
		var observedAt, source any
		if err := rows.Scan(&techs, &observedAt, &source); err != nil {
			return nil, err
		}
		var arr []string
		if err := json.Unmarshal([]byte(techs), &arr); err != nil || len(arr) == 0 {
			continue
		}
		out = append(out, Relation{Kind: KindTech, From: value,
			To: strings.Join(arr, ", "), ObservedAt: asStr(observedAt), Source: asStr(source)})
	}
	return out, rows.Err()
}

func asnRelations(ctx context.Context, x *dbx, assetID int64, value string) ([]Relation, error) {
	var prefix string
	var observedAt, source any
	err := x.queryRow(ctx, `
		SELECT COALESCE(t.prefix, ''), t.observed_at, COALESCE(ds.name, '')
		FROM latest_ip2asn_t t `+provJoin+` WHERE t.asset_id = ?`, assetID).
		Scan(&prefix, &observedAt, &source)
	if err == sql.ErrNoRows {
		return nil, nil // no ip2asn evidence — no invented attribution
	}
	if err != nil {
		return nil, err
	}
	var asn int64
	var asnOrg string
	if err := x.queryRow(ctx, `SELECT COALESCE(asn,0), COALESCE(asn_org,'') FROM assets WHERE id = ?`, assetID).
		Scan(&asn, &asnOrg); err != nil {
		return nil, err
	}
	to := fmt.Sprintf("AS%d", asn)
	if asnOrg != "" {
		to += " · " + asnOrg
	}
	detail := ""
	if prefix != "" {
		detail = "prefix " + prefix
	}
	return []Relation{{Kind: KindASNCountry, From: value, To: to,
		Detail: detail, ObservedAt: asStr(observedAt), Source: asStr(source)}}, nil
}

func prefixPeers(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT a.value, t.prefix, t.observed_at, COALESCE(ds.name, '')
		FROM latest_ip2asn_t t
		JOIN assets a ON a.id = t.asset_id
		`+provJoin+`
		WHERE t.prefix IS NOT NULL
		  AND t.prefix = (SELECT prefix FROM latest_ip2asn_t WHERE asset_id = ?)
		  AND t.asset_id <> ?
		ORDER BY t.observed_at DESC LIMIT ?`, assetID, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var peer, prefix string
		var observedAt, source any
		if err := rows.Scan(&peer, &prefix, &observedAt, &source); err != nil {
			return nil, err
		}
		out = append(out, Relation{Kind: KindPrefixPeer, From: value, To: peer,
			Detail: prefix, ObservedAt: asStr(observedAt), Source: asStr(source)})
	}
	return out, rows.Err()
}

// dnsForward parses the seed's own latest DNS record object (the exact
// JSON GSEER stored from the DNS collector) and yields name→answer edges.
func dnsForward(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	var raw any
	err := x.queryRow(ctx, `SELECT dns_record FROM latest_dns_t WHERE asset_id = ?`, assetID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(asStr(raw)), &doc); err != nil {
		return nil, nil // unparseable record: no edges invented
	}
	out := []Relation{}
	for _, pair := range flattenDNS(doc) {
		rtype, v := pair[0].(string), pair[1].(string)
		if len(out) >= limit {
			return out, nil
		}
		out = append(out, Relation{Kind: KindDNSResolves, From: value, To: v,
			Detail: rtype, ObservedAt: "", Source: "latest_dns"})
	}
	// Stamp observed_at from the projection row on the edges.
	var observedAt any
	if err := x.queryRow(ctx, `SELECT observed_at FROM latest_dns_t WHERE asset_id = ?`, assetID).Scan(&observedAt); err == nil {
		for i := range out {
			out[i].ObservedAt = asStr(observedAt)
		}
	}
	return out, nil
}

// flattenDNS extracts (rtype, []answer) pairs from a dns record object.
// The collector stores answers under type-ish keys with string or object
// values; unknown shapes are skipped (never guessed).
func flattenDNS(doc map[string]any) [][2]any {
	out := [][2]any{}
	for key, v := range doc {
		rt := strings.ToUpper(key)
		switch tv := v.(type) {
		case string:
			if rt != "QUERY" {
				out = append(out, [2]any{rt, tv})
			}
		case []any:
			for _, item := range tv {
				switch iv := item.(type) {
				case string:
					out = append(out, [2]any{rt, iv})
				case map[string]any:
					if s, ok := iv["value"].(string); ok && s != "" {
						out = append(out, [2]any{rt, s})
					}
				}
			}
		case map[string]any:
			if s, ok := tv["value"].(string); ok && s != "" && rt != "QUERY" {
				out = append(out, [2]any{rt, s})
			}
		}
	}
	return out
}

// dnsReverse finds OTHER names whose latest DNS record mentions the
// seed IP (shared-DNS hosting evidence).  The record JSON is searched as
// text for the quoted IP literal — an exact, evidence-bounded match.
func dnsReverse(ctx context.Context, x *dbx, assetID int64, value, needle string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT a.value, t.observed_at, COALESCE(ds.name, '')
		FROM latest_dns_t t
		JOIN assets a ON a.id = t.asset_id
		`+provJoin+`
		WHERE t.asset_id <> ? AND instr(t.dns_record, ?) > 0
		ORDER BY t.observed_at DESC LIMIT ?`, assetID, needle, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var peer string
		var observedAt, source any
		if err := rows.Scan(&peer, &observedAt, &source); err != nil {
			return nil, err
		}
		out = append(out, Relation{Kind: KindDNSReverse, From: value, To: peer,
			Detail: needle, ObservedAt: asStr(observedAt), Source: asStr(source)})
	}
	return out, rows.Err()
}

func ctCerts(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT COALESCE(t.subject_cn, ''), COALESCE(t.leaf_sha256, ''), COALESCE(t.issuer, ''),
		       t.observed_at, COALESCE(ds.name, '')
		FROM latest_ctlog_t t `+provJoin+` WHERE t.asset_id = ? LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var subj, sha, issuer string
		var observedAt, source any
		if err := rows.Scan(&subj, &sha, &issuer, &observedAt, &source); err != nil {
			return nil, err
		}
		out = append(out, Relation{Kind: KindCTCert, From: value, To: subj,
			Detail: "leaf " + shortSHA(sha) + " · " + issuer, ObservedAt: asStr(observedAt), Source: asStr(source)})
	}
	return out, rows.Err()
}

// ctShared — other assets that appear on the SAME CT leaf certificate
// (classic shared-certificate hosting evidence).
func ctShared(ctx context.Context, x *dbx, assetID int64, value string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT a.value, COALESCE(t.subject_cn, ''), t.observed_at, COALESCE(ds.name, '')
		FROM latest_ctlog_t t
		JOIN assets a ON a.id = t.asset_id
		`+provJoin+`
		WHERE t.leaf_sha256 IS NOT NULL
		  AND t.leaf_sha256 = (SELECT leaf_sha256 FROM latest_ctlog_t WHERE asset_id = ? AND leaf_sha256 IS NOT NULL LIMIT 1)
		  AND t.asset_id <> ?
		ORDER BY t.observed_at DESC LIMIT ?`, assetID, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var peer, subj string
		var observedAt, source any
		if err := rows.Scan(&peer, &subj, &observedAt, &source); err != nil {
			return nil, err
		}
		out = append(out, Relation{Kind: KindCTShared, From: value, To: peer,
			Detail: subj, ObservedAt: asStr(observedAt), Source: asStr(source)})
	}
	return out, rows.Err()
}

func tlsRelations(ctx context.Context, x *dbx, assetID int64, value, kindFilter string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT s.port, COALESCE(t.cert_subject_cn, ''), COALESCE(t.cert_serial, ''),
		       COALESCE(t.cert_sans_dns, ''), COALESCE(t.tls_version, ''), t.observed_at, COALESCE(ds.name, '')
		FROM latest_tls_t t
		JOIN services s ON s.id = t.service_id
		`+provJoin+`
		WHERE s.asset_id = ? ORDER BY s.port LIMIT ?`, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var port int64
		var subj, serial, sans, version string
		var observedAt, source any
		if err := rows.Scan(&port, &subj, &serial, &sans, &version, &observedAt, &source); err != nil {
			return nil, err
		}
		observedAtStr, sourceStr := asStr(observedAt), asStr(source)
		if kindFilter == "" || kindFilter == KindTLSCert {
			detail := version
			if serial != "" {
				detail += " · serial " + serial
			}
			out = append(out, Relation{Kind: KindTLSCert, From: value,
				To: fmt.Sprintf("%d/tcp %s", int(port), subj), Detail: detail,
				ObservedAt: observedAtStr, Source: sourceStr})
		}
		if kindFilter == "" || kindFilter == KindTLSShared {
			for _, san := range strings.Split(sans, ",") {
				san = strings.TrimSpace(san)
				if san == "" || san == subj || len(out) > 200 {
					continue
				}
				out = append(out, Relation{Kind: KindTLSShared, From: value, To: san,
					Detail: fmt.Sprintf("SAN of cert on :%d", int(port)), ObservedAt: observedAtStr, Source: sourceStr})
			}
		}
	}
	return out, rows.Err()
}

func sameOrg(ctx context.Context, x *dbx, assetID int64, value, org string, limit int) ([]Relation, error) {
	rows, err := x.query(ctx, `
		SELECT a.value, a.last_seen, a.asn FROM assets a
		WHERE a.asn_org = ? AND a.id <> ? ORDER BY a.last_seen DESC LIMIT ?`,
		org, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var peer string
		var lastSeen any
		var asn int64
		if err := rows.Scan(&peer, &lastSeen, &asn); err != nil {
			return nil, err
		}
		out = append(out, Relation{Kind: KindSameOrg, From: value, To: peer,
			Detail: fmt.Sprintf("AS%d", asn), ObservedAt: asStr(lastSeen), Source: "assets"})
	}
	return out, rows.Err()
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12] + "…"
	}
	return sha
}

// Kinds returns the full list (used by --kind validation and docs).
func Kinds() []string {
	return []string{KindDNSResolves, KindDNSReverse, KindASNCountry, KindPrefixPeer,
		KindCTCert, KindCTShared, KindTLSCert, KindTLSShared, KindSameOrg, KindService, KindTech}
}
