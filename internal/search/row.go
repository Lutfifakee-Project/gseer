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

package search

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
)

// row.go — the result row shape and the projection-aware scanner.
//
// The planner lets callers project a SUBSET of the search_index columns,
// so the scanner binds targets BY COLUMN NAME from the result's field
// descriptions instead of positional scanning.

// Row is one search_index row (the v0.0.1 service-granular result).
// JSON tags are the API wire shape (SPEC-07).
type Row struct {
	RowID   int64  `json:"row_id"`
	RowKind string `json:"row_kind"` // service | asset-only
	AssetID int64  `json:"asset_id"`

	AssetKind  string `json:"asset_kind"` // ip | domain | hostname
	AssetValue string `json:"asset_value"`

	IP       *string `json:"ip,omitempty"`
	Domain   *string `json:"domain,omitempty"`
	Hostname *string `json:"hostname,omitempty"`

	ASN    *int    `json:"asn,omitempty"`
	ASNOrg *string `json:"asn_org,omitempty"`

	GeoCountry *string `json:"geo_country,omitempty"`
	GeoRegion  *string `json:"geo_region,omitempty"`
	GeoCity    *string `json:"geo_city,omitempty"`

	Port      *int    `json:"port,omitempty"`
	Transport *string `json:"transport,omitempty"`
	Protocol  *string `json:"protocol,omitempty"`
	Name      *string `json:"name,omitempty"`
	Product   *string `json:"product,omitempty"`
	Version   *string `json:"version,omitempty"`

	HTTPStatus *int    `json:"http_status,omitempty"`
	HTTPTitle  *string `json:"http_title,omitempty"`
	HTTPServer *string `json:"http_server,omitempty"`

	TLSVersion       *string    `json:"tls_version,omitempty"`
	TLSCertSubjectCN *string    `json:"tls_cert_subject_cn,omitempty"`
	TLSCertIssuerCN  *string    `json:"tls_cert_issuer_cn,omitempty"`
	TLSCertExpiry    *time.Time `json:"tls_cert_expiry,omitempty"`
	// v0.3.2 certificate breadth (migration 0021 PG / 0005 personal
	// SQLite): the serial (hex) and the SAN DNS entries as a
	// comma-joined string, projected from the TLS observation evidence.
	TLSCertSerial  *string `json:"tls_cert_serial,omitempty"`
	TLSCertSansDNS *string `json:"tls_cert_sans_dns,omitempty"`

	// R39 P2 completion (r23): the CT log sighting columns are
	// searchable AND projectable — the timestamps surface as the raw
	// stored strings (ct fields are not sortable; WHERE semantics are
	// unchanged).
	CTLog           *string `json:"ct_log,omitempty"`
	CTEntryType     *string `json:"ct_entry_type,omitempty"`
	CTSubjectCN     *string `json:"ct_subject_cn,omitempty"`
	CTIssuer        *string `json:"ct_issuer,omitempty"`
	CTLeafSHA256    *string `json:"ct_leaf_sha256,omitempty"`
	CTNotBefore     *string `json:"ct_not_before,omitempty"`
	CTNotAfter      *string `json:"ct_not_after,omitempty"`
	CTCertTimestamp *string `json:"ct_cert_timestamp,omitempty"`

	Technologies []string `json:"technologies,omitempty"`
	Sources      []string `json:"sources,omitempty"`

	// R36 P3/P4 evidence-quality fields (migration 0022 PG / 0006
	// personal SQLite): the provenance families, the honest per-asset
	// observation recency, and the coverage class.
	EvidenceKinds []string   `json:"evidence_kinds,omitempty"`
	LastObserved  *time.Time `json:"last_observed,omitempty"`
	CoverageClass *string    `json:"coverage_class,omitempty"`

	// R37 search-field expansion: the asset's latest IP-to-ASN/BGP
	// attribution prefix, the service banner evidence, the issuing
	// organization of the latest certificate, and the RAW captured
	// headers JSON (per-name lookup happens in the WHERE clause; the
	// whole object is projectable).
	IPPrefix      *string `json:"ip_prefix,omitempty"`
	Banner        *string `json:"banner,omitempty"`
	CertIssuerOrg *string `json:"cert_issuer_org,omitempty"`
	HTTPHeaders   *string `json:"http_headers,omitempty"`

	// evidenceJSON is the raw JSON-array scan target for
	// evidence_kinds (JSONB on PG, JSON text on SQLite); after Scan it
	// unmarshals into EvidenceKinds.
	evidenceJSON []byte `json:"-"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Stale     bool      `json:"stale"`

	// ipPrefix is the raw inet scan target (PG type inet cannot scan
	// into *string); after Scan it reduces to the IP string form.
	ipPrefix *netip.Prefix `json:"-"`
}

// sortValue renders the row's value for the given canonical sort field
// (the cursor payload form): stringified, with isNull=true when the
// column was SQL NULL.
//
// The per-field dispatch is table-driven: stringSortFields / intSortFields
// cover the pointer columns, the switch below the nullable time columns
// and the two never-null text columns.
var stringSortFields = map[string]func(*Row) *string{
	"ip":                  func(r *Row) *string { return r.IP },
	"domain":              func(r *Row) *string { return r.Domain },
	"hostname":            func(r *Row) *string { return r.Hostname },
	"asn_org":             func(r *Row) *string { return r.ASNOrg },
	"geo_country":         func(r *Row) *string { return r.GeoCountry },
	"geo_region":          func(r *Row) *string { return r.GeoRegion },
	"geo_city":            func(r *Row) *string { return r.GeoCity },
	"transport":           func(r *Row) *string { return r.Transport },
	"protocol":            func(r *Row) *string { return r.Protocol },
	"name":                func(r *Row) *string { return r.Name },
	"product":             func(r *Row) *string { return r.Product },
	"version":             func(r *Row) *string { return r.Version },
	"http.title":          func(r *Row) *string { return r.HTTPTitle },
	"http.server":         func(r *Row) *string { return r.HTTPServer },
	"tls.version":         func(r *Row) *string { return r.TLSVersion },
	"tls.cert_subject_cn": func(r *Row) *string { return r.TLSCertSubjectCN },
	"tls.cert_issuer_cn":  func(r *Row) *string { return r.TLSCertIssuerCN },
	"tls.cert_serial":     func(r *Row) *string { return r.TLSCertSerial },
	"tls.cert_sans_dns":   func(r *Row) *string { return r.TLSCertSansDNS },
	"ct.log":              func(r *Row) *string { return r.CTLog },
	"ct.entry_type":       func(r *Row) *string { return r.CTEntryType },
	"ct.subject":          func(r *Row) *string { return r.CTSubjectCN },
	"ct.issuer":           func(r *Row) *string { return r.CTIssuer },
	"ct.leaf_sha256":      func(r *Row) *string { return r.CTLeafSHA256 },
	"ct.not_before":       func(r *Row) *string { return r.CTNotBefore },
	"ct.not_after":        func(r *Row) *string { return r.CTNotAfter },
	"ct.cert_timestamp":   func(r *Row) *string { return r.CTCertTimestamp },
}

var intSortFields = map[string]func(*Row) *int{
	"port":        func(r *Row) *int { return r.Port },
	"asn":         func(r *Row) *int { return r.ASN },
	"http.status": func(r *Row) *int { return r.HTTPStatus },
}

func (r *Row) sortValue(field string) (string, bool) {
	if get, ok := stringSortFields[field]; ok {
		if p := get(r); p != nil {
			return *p, false
		}
		return "", true
	}
	if get, ok := intSortFields[field]; ok {
		if p := get(r); p != nil {
			return fmt.Sprintf("%d", *p), false
		}
		return "", true
	}
	switch field {
	case "asset_value":
		return r.AssetValue, false
	case "asset_kind":
		return r.AssetKind, false
	case "coverage":
		// R45: the cursor carries the evidence-strength RANK (planner.
		// CoverageRank), not the class string — the ORDER BY is the rank
		// CASE, so the payload must be numeric for page 2 to resume.
		class := "unclassified"
		if r.CoverageClass != nil {
			class = *r.CoverageClass
		}
		return fmt.Sprintf("%d", planner.CoverageRank(class)), false
	case "first_seen", "last_seen", "tls.cert_expiry":
		var t time.Time
		switch field {
		case "first_seen":
			t = r.FirstSeen
		case "last_seen":
			t = r.LastSeen
		case "tls.cert_expiry":
			if r.TLSCertExpiry == nil {
				return "", true
			}
			t = *r.TLSCertExpiry
		}
		return t.UTC().Format(time.RFC3339Nano), false
	}
	return "", true
}

// scanRow binds one result row to a Row by column name.
//
// The column → target dispatch is the rowScanTargets table (the planner
// owns the projection list; unknown columns fall through to a discard
// buffer so the row stays consumable).
var rowScanTargets = map[string]func(*Row) any{
	"row_id":      func(r *Row) any { return &r.RowID },
	"row_kind":    func(r *Row) any { return &r.RowKind },
	"asset_id":    func(r *Row) any { return &r.AssetID },
	"asset_kind":  func(r *Row) any { return &r.AssetKind },
	"asset_value": func(r *Row) any { return &r.AssetValue },
	// ip is PG type inet; scan through netip.Prefix and reduce a
	// single-host prefix (/32, /128) to the bare address string.
	"ip":                func(r *Row) any { return &r.ipPrefix },
	"domain":            func(r *Row) any { return &r.Domain },
	"hostname":          func(r *Row) any { return &r.Hostname },
	"asn":               func(r *Row) any { return &r.ASN },
	"asn_org":           func(r *Row) any { return &r.ASNOrg },
	"geo_country":       func(r *Row) any { return &r.GeoCountry },
	"geo_region":        func(r *Row) any { return &r.GeoRegion },
	"geo_city":          func(r *Row) any { return &r.GeoCity },
	"port":              func(r *Row) any { return &r.Port },
	"transport":         func(r *Row) any { return &r.Transport },
	"protocol":          func(r *Row) any { return &r.Protocol },
	"name":              func(r *Row) any { return &r.Name },
	"product":           func(r *Row) any { return &r.Product },
	"version":           func(r *Row) any { return &r.Version },
	"http_status":       func(r *Row) any { return &r.HTTPStatus },
	"http_title":        func(r *Row) any { return &r.HTTPTitle },
	"http_server":       func(r *Row) any { return &r.HTTPServer },
	"tls_version":       func(r *Row) any { return &r.TLSVersion },
	"cert_subject_cn":   func(r *Row) any { return &r.TLSCertSubjectCN },
	"cert_issuer_cn":    func(r *Row) any { return &r.TLSCertIssuerCN },
	"cert_expiry":       func(r *Row) any { return &r.TLSCertExpiry },
	"cert_serial":       func(r *Row) any { return &r.TLSCertSerial },
	"cert_sans_dns":     func(r *Row) any { return &r.TLSCertSansDNS },
	"technologies":      func(r *Row) any { return &r.Technologies },
	"sources":           func(r *Row) any { return &r.Sources },
	"evidence_kinds":    func(r *Row) any { return &r.evidenceJSON },
	"last_observed":     func(r *Row) any { return &r.LastObserved },
	"coverage_class":    func(r *Row) any { return &r.CoverageClass },
	"ip_prefix":         func(r *Row) any { return &r.IPPrefix },
	"banner":            func(r *Row) any { return &r.Banner },
	"cert_issuer_org":   func(r *Row) any { return &r.CertIssuerOrg },
	"http_headers":      func(r *Row) any { return &r.HTTPHeaders },
	"ct_log":            func(r *Row) any { return &r.CTLog },
	"ct_entry_type":     func(r *Row) any { return &r.CTEntryType },
	"ct_subject_cn":     func(r *Row) any { return &r.CTSubjectCN },
	"ct_issuer":         func(r *Row) any { return &r.CTIssuer },
	"ct_leaf_sha256":    func(r *Row) any { return &r.CTLeafSHA256 },
	"ct_not_before":     func(r *Row) any { return &r.CTNotBefore },
	"ct_not_after":      func(r *Row) any { return &r.CTNotAfter },
	"ct_cert_timestamp": func(r *Row) any { return &r.CTCertTimestamp },
	"first_seen":        func(r *Row) any { return &r.FirstSeen },
	"last_seen":         func(r *Row) any { return &r.LastSeen },
	"stale":             func(r *Row) any { return &r.Stale },
}

func scanRow(rows pgx.Rows) (Row, error) {
	var r Row
	fields := rows.FieldDescriptions()
	ptrs := make([]any, len(fields))

	for i, f := range fields {
		if get, ok := rowScanTargets[f.Name]; ok {
			ptrs[i] = get(&r)
			continue
		}
		// Unknown projected column — scan into a discard buffer so
		// the row stays consumable.
		var discard any
		ptrs[i] = &discard
	}
	if err := rows.Scan(ptrs...); err != nil {
		return Row{}, err
	}
	if r.ipPrefix != nil {
		s := formatPrefix(*r.ipPrefix)
		r.IP = &s
	}
	if len(r.evidenceJSON) > 0 {
		var kinds []string
		if err := json.Unmarshal(r.evidenceJSON, &kinds); err == nil && len(kinds) > 0 {
			r.EvidenceKinds = kinds
		}
	}
	return r, nil
}

// formatPrefix renders an inet value: single-host prefixes collapse to
// the bare address (203.0.113.10/32 → 203.0.113.10).
func formatPrefix(p netip.Prefix) string {
	if (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 128) {
		return p.Addr().String()
	}
	return p.String()
}
