// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package search

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
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
	HTTPBody   *string `json:"http_body,omitempty"`
	HTTPHeader *string `json:"http_header,omitempty"`

	TLSVersion       *string    `json:"tls_version,omitempty"`
	TLSCertSubjectCN *string    `json:"tls_cert_subject_cn,omitempty"`
	TLSCertIssuerCN  *string    `json:"tls_cert_issuer_cn,omitempty"`
	TLSCertExpiry    *time.Time `json:"tls_cert_expiry,omitempty"`
	// v0.3.2 certificate breadth (migration 0021 PG / 0005 personal
	// SQLite): the serial (hex) and the SAN DNS entries as a
	// comma-joined string, projected from the TLS observation evidence.
	TLSCertSerial  *string `json:"tls_cert_serial,omitempty"`
	TLSCertSansDNS *string `json:"tls_cert_sans_dns,omitempty"`

	Technologies []string `json:"technologies,omitempty"`
	Sources      []string `json:"sources,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// v0.3.2 (migration 0022 PG / 0006 personal SQLite): the row's REAL
	// evidence time — the newest observation's observed_at.  Unlike
	// last_seen (bumped by every ingest/import), observed_at only moves
	// when new evidence lands.  Asset-only rows without any observation
	// carry NULL (omitted in JSON).
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Stale      bool       `json:"stale"`

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
	"http.body":           func(r *Row) *string { return r.HTTPBody },
	"http.header":         func(r *Row) *string { return r.HTTPHeader },
	"tls.version":         func(r *Row) *string { return r.TLSVersion },
	"tls.cert_subject_cn": func(r *Row) *string { return r.TLSCertSubjectCN },
	"tls.cert_issuer_cn":  func(r *Row) *string { return r.TLSCertIssuerCN },
	"tls.cert_serial":     func(r *Row) *string { return r.TLSCertSerial },
	"tls.cert_sans_dns":   func(r *Row) *string { return r.TLSCertSansDNS },
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
	case "first_seen", "last_seen", "observed_at", "tls.cert_expiry":
		var t time.Time
		switch field {
		case "first_seen":
			t = r.FirstSeen
		case "last_seen":
			t = r.LastSeen
		case "observed_at":
			if r.ObservedAt == nil {
				return "", true
			}
			t = *r.ObservedAt
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
	"ip":              func(r *Row) any { return &r.ipPrefix },
	"domain":          func(r *Row) any { return &r.Domain },
	"hostname":        func(r *Row) any { return &r.Hostname },
	"asn":             func(r *Row) any { return &r.ASN },
	"asn_org":         func(r *Row) any { return &r.ASNOrg },
	"geo_country":     func(r *Row) any { return &r.GeoCountry },
	"geo_region":      func(r *Row) any { return &r.GeoRegion },
	"geo_city":        func(r *Row) any { return &r.GeoCity },
	"port":            func(r *Row) any { return &r.Port },
	"transport":       func(r *Row) any { return &r.Transport },
	"protocol":        func(r *Row) any { return &r.Protocol },
	"name":            func(r *Row) any { return &r.Name },
	"product":         func(r *Row) any { return &r.Product },
	"version":         func(r *Row) any { return &r.Version },
	"http_status":     func(r *Row) any { return &r.HTTPStatus },
	"http_title":      func(r *Row) any { return &r.HTTPTitle },
	"http_server":     func(r *Row) any { return &r.HTTPServer },
	"http_body":       func(r *Row) any { return &r.HTTPBody },
	"http_header":     func(r *Row) any { return &r.HTTPHeader },
	"tls_version":     func(r *Row) any { return &r.TLSVersion },
	"cert_subject_cn": func(r *Row) any { return &r.TLSCertSubjectCN },
	"cert_issuer_cn":  func(r *Row) any { return &r.TLSCertIssuerCN },
	"cert_expiry":     func(r *Row) any { return &r.TLSCertExpiry },
	"cert_serial":     func(r *Row) any { return &r.TLSCertSerial },
	"cert_sans_dns":   func(r *Row) any { return &r.TLSCertSansDNS },
	"technologies":    func(r *Row) any { return &r.Technologies },
	"sources":         func(r *Row) any { return &r.Sources },
	"first_seen":      func(r *Row) any { return &r.FirstSeen },
	"last_seen":       func(r *Row) any { return &r.LastSeen },
	"observed_at":     func(r *Row) any { return &r.ObservedAt },
	"stale":           func(r *Row) any { return &r.Stale },
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

// ---------------------------------------------------------------------------
// Projection pruning (v0.3.2-r2 owner finding)
// ---------------------------------------------------------------------------
//
// The planners now ALWAYS include the mandatory identity/metadata
// columns and the ORDER BY columns in the SELECT (the keyset cursor
// reads them off the scanned last row).  The wire contract, however, is
// "mandatory block + exactly the requested fields": the service prunes
// the scanned rows back down so no sort/projection column leaks into
// the output on ANY surface (CLI JSON/YAML/CSV/NDJSON/table, REST,
// dashboard).  Pruning runs AFTER cursor derivation.

// pruneColumnClearers nils the OPTIONAL columns of a Row (everything
// outside the mandatory identity/metadata block).  ip clears both the
// exposed string and the raw inet scan slot.
var pruneColumnClearers = map[string]func(*Row){
	"ip":              func(r *Row) { r.ipPrefix, r.IP = nil, nil },
	"domain":          func(r *Row) { r.Domain = nil },
	"hostname":        func(r *Row) { r.Hostname = nil },
	"asn":             func(r *Row) { r.ASN = nil },
	"asn_org":         func(r *Row) { r.ASNOrg = nil },
	"geo_country":     func(r *Row) { r.GeoCountry = nil },
	"geo_region":      func(r *Row) { r.GeoRegion = nil },
	"geo_city":        func(r *Row) { r.GeoCity = nil },
	"port":            func(r *Row) { r.Port = nil },
	"transport":       func(r *Row) { r.Transport = nil },
	"protocol":        func(r *Row) { r.Protocol = nil },
	"name":            func(r *Row) { r.Name = nil },
	"product":         func(r *Row) { r.Product = nil },
	"version":         func(r *Row) { r.Version = nil },
	"http_status":     func(r *Row) { r.HTTPStatus = nil },
	"http_title":      func(r *Row) { r.HTTPTitle = nil },
	"http_server":     func(r *Row) { r.HTTPServer = nil },
	"http_body":       func(r *Row) { r.HTTPBody = nil },
	"http_header":     func(r *Row) { r.HTTPHeader = nil },
	"tls_version":     func(r *Row) { r.TLSVersion = nil },
	"cert_subject_cn": func(r *Row) { r.TLSCertSubjectCN = nil },
	"cert_issuer_cn":  func(r *Row) { r.TLSCertIssuerCN = nil },
	"cert_expiry":     func(r *Row) { r.TLSCertExpiry = nil },
	"cert_serial":     func(r *Row) { r.TLSCertSerial = nil },
	"cert_sans_dns":   func(r *Row) { r.TLSCertSansDNS = nil },
	"technologies":    func(r *Row) { r.Technologies = nil },
	"sources":         func(r *Row) { r.Sources = nil },
}

// PruneToProjection nils out the optional fields the caller did not
// request.  Mandatory identity/metadata fields are never touched (a
// custom projection must not zero or erase them — the r2 owner
// finding).  Empty/nil fields (the default all-columns projection) is a
// no-op, so the default behavior is byte-identical.
func PruneToProjection(rows []Row, fields []string) {
	if len(fields) == 0 || len(rows) == 0 {
		return
	}
	keep := make(map[string]bool, len(fields)+len(planner.MandatoryProjectionColumns()))
	for _, f := range fields {
		if col := planner.ResolveProjectionColumn(f); col != "" {
			keep[col] = true
		}
	}
	for i, r := range rows {
		for col, clear := range pruneColumnClearers {
			if !keep[col] {
				clear(&r)
			}
		}
		rows[i] = r // #nosec G602 -- i is the range index over rows itself; in-bounds by construction
	}
}

// VisibleColumns returns the canonical column order for tabular
// renderers (CSV): the mandatory identity/metadata block plus the
// requested fields, in canonical view order.  Returns nil when fields
// is empty — meaning the default all-columns projection.
func VisibleColumns(fields []string) []string {
	if len(fields) == 0 {
		return nil
	}
	keep := make(map[string]bool, len(fields)+9)
	for _, f := range fields {
		if col := planner.ResolveProjectionColumn(f); col != "" {
			keep[col] = true
		}
	}
	mandatory := planner.MandatoryProjectionColumns()
	mset := make(map[string]bool, len(mandatory))
	for _, c := range mandatory {
		mset[c] = true
	}
	out := make([]string, 0, len(keep)+len(mset))
	for _, c := range planner.AllSearchColumns() {
		if mset[c] || keep[c] {
			out = append(out, c)
		}
	}
	return out
}

// csvCellRenderers maps every projected column to its CSV cell renderer
// (a table keeps the renderer flat as the column set grows).  Times
// render as RFC3339Nano UTC, lists comma-joined, SQL NULL → "".
var csvCellRenderers = map[string]func(*Row) string{
	"row_id":          func(r *Row) string { return strconv.FormatInt(r.RowID, 10) },
	"row_kind":        func(r *Row) string { return r.RowKind },
	"asset_id":        func(r *Row) string { return strconv.FormatInt(r.AssetID, 10) },
	"asset_kind":      func(r *Row) string { return r.AssetKind },
	"asset_value":     func(r *Row) string { return r.AssetValue },
	"ip":              func(r *Row) string { return derefStr(r.IP) },
	"domain":          func(r *Row) string { return derefStr(r.Domain) },
	"hostname":        func(r *Row) string { return derefStr(r.Hostname) },
	"asn":             func(r *Row) string { return intPtrCell(r.ASN) },
	"asn_org":         func(r *Row) string { return derefStr(r.ASNOrg) },
	"geo_country":     func(r *Row) string { return derefStr(r.GeoCountry) },
	"geo_region":      func(r *Row) string { return derefStr(r.GeoRegion) },
	"geo_city":        func(r *Row) string { return derefStr(r.GeoCity) },
	"port":            func(r *Row) string { return intPtrCell(r.Port) },
	"transport":       func(r *Row) string { return derefStr(r.Transport) },
	"protocol":        func(r *Row) string { return derefStr(r.Protocol) },
	"name":            func(r *Row) string { return derefStr(r.Name) },
	"product":         func(r *Row) string { return derefStr(r.Product) },
	"version":         func(r *Row) string { return derefStr(r.Version) },
	"http_status":     func(r *Row) string { return intPtrCell(r.HTTPStatus) },
	"http_title":      func(r *Row) string { return derefStr(r.HTTPTitle) },
	"http_server":     func(r *Row) string { return derefStr(r.HTTPServer) },
	"http_body":       func(r *Row) string { return derefStr(r.HTTPBody) },
	"http_header":     func(r *Row) string { return derefStr(r.HTTPHeader) },
	"tls_version":     func(r *Row) string { return derefStr(r.TLSVersion) },
	"cert_subject_cn": func(r *Row) string { return derefStr(r.TLSCertSubjectCN) },
	"cert_issuer_cn":  func(r *Row) string { return derefStr(r.TLSCertIssuerCN) },
	"cert_expiry":     func(r *Row) string { return timePtrCell(r.TLSCertExpiry) },
	"cert_serial":     func(r *Row) string { return derefStr(r.TLSCertSerial) },
	"cert_sans_dns":   func(r *Row) string { return derefStr(r.TLSCertSansDNS) },
	"technologies":    func(r *Row) string { return strings.Join(r.Technologies, ",") },
	"sources":         func(r *Row) string { return strings.Join(r.Sources, ",") },
	"first_seen":      func(r *Row) string { return r.FirstSeen.UTC().Format(time.RFC3339Nano) },
	"last_seen":       func(r *Row) string { return r.LastSeen.UTC().Format(time.RFC3339Nano) },
	"observed_at":     func(r *Row) string { return timePtrCell(r.ObservedAt) },
	"stale": func(r *Row) string {
		if r.Stale {
			return "true"
		}
		return "false"
	},
}

// CSVCell renders one column's value for the tabular (CSV) renderer.
// Unknown columns render as "".
func (r *Row) CSVCell(col string) string {
	if f, ok := csvCellRenderers[col]; ok {
		return f(r)
	}
	return ""
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intPtrCell(i *int) string {
	if i == nil {
		return ""
	}
	return strconv.Itoa(*i)
}

func timePtrCell(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
