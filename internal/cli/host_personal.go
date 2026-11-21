// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// host_personal.go — the personal-mode (SQLite) half of `gseer host`:
// the same report shape and the same strictly read-only contract, one
// embedded database file instead of PostgreSQL.  The personal schema
// mirrors the PostgreSQL tables — migration 0001 even ships the same
// latest_http / latest_tls / latest_fingerprints views — so this report
// is field-for-field what the self-hosted path prints; only the dialect
// differs (TEXT timestamps via sqlite.ParseTS, JSON-encoded sources and
// technologies, no ::text casts, printf instead of format).
//
// v0.3.2 fix: the personal profile used to refuse `host` with
// E_PROFILE_UNSUPPORTED ("not wired for personal mode yet") — a dead end
// in the Easy-to-Use journey for exactly the provenance/timestamps
// surface the operator needs after their first real collection.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// loadHostReportPersonal runs the three read-only queries behind
// `gseer host` against the personal SQLite store.
func loadHostReportPersonal(ctx context.Context, db *sql.DB, identifier string) (*hostReport, bool, error) {
	rep := &hostReport{Observations: hostObservationStats{BySource: map[string]int64{}}}

	// 1. The asset (value/ip/hostname/domain; ambiguous matches resolve
	//    to the oldest row — identity (kind, value) is unique, the
	//    mirror columns can collide across kinds — same rule as PG).
	var sourcesJSON string
	var asn sql.NullInt64
	var firstSeen, lastSeen string
	var stale int
	err := db.QueryRowContext(ctx, `
SELECT id, kind, value,
       COALESCE(ip, ''), COALESCE(domain, ''), COALESCE(hostname, ''),
       asn, COALESCE(asn_org, ''),
       COALESCE(geo_country, ''), COALESCE(geo_region, ''), COALESCE(geo_city, ''),
       sources, first_seen, last_seen, stale
FROM assets
WHERE value = ?1 OR ip = ?1 OR hostname = ?1 OR domain = ?1
ORDER BY id
LIMIT 1`, identifier).
		Scan(&rep.Asset.ID, &rep.Asset.Kind, &rep.Asset.Value,
			&rep.Asset.IP, &rep.Asset.Domain, &rep.Asset.Hostname,
			&asn, &rep.Asset.ASNOrg,
			&rep.Asset.Country, &rep.Asset.Region, &rep.Asset.City,
			&sourcesJSON, &firstSeen, &lastSeen, &stale)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if asn.Valid {
		v := int(asn.Int64)
		rep.Asset.ASN = &v
	}
	_ = json.Unmarshal([]byte(sourcesJSON), &rep.Asset.Sources)
	if rep.Asset.Sources == nil {
		rep.Asset.Sources = []string{}
	}
	rep.Asset.FirstSeen = personalTSTime(firstSeen)
	rep.Asset.LastSeen = personalTSTime(lastSeen)
	rep.Asset.Stale = stale != 0

	// 2. Services with their latest HTTP/TLS/fingerprint state — the
	//    same latest_* views the search_index view joins.
	rows, err := db.QueryContext(ctx, `
SELECT s.id, s.port, s.transport, s.protocol, s.name, s.product, s.version,
       s.last_seen, s.stale,
       h.status, COALESCE(h.title, ''), COALESCE(h.server, ''),
       COALESCE(tls.tls_version, ''),
       COALESCE(fp.technologies, '[]')
FROM services s
LEFT JOIN latest_http h          ON h.service_id = s.id
LEFT JOIN latest_tls tls         ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
WHERE s.asset_id = ?1
ORDER BY s.port, s.transport`, rep.Asset.ID)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s hostService
		var status sql.NullInt64
		var techJSON string
		var lastSeen string
		var stale int
		if err := rows.Scan(&s.ID, &s.Port, &s.Transport, &s.Protocol, &s.Name, &s.Product, &s.Version,
			&lastSeen, &stale,
			&status, &s.HTTPTitle, &s.HTTPServer,
			&s.TLSVersion, &techJSON); err != nil {
			return nil, false, err
		}
		if status.Valid {
			v := int(status.Int64)
			s.HTTPStatus = &v
		}
		_ = json.Unmarshal([]byte(techJSON), &s.Tech)
		if s.Tech == nil {
			s.Tech = []string{}
		}
		s.LastSeen = personalTSTime(lastSeen)
		s.Stale = stale != 0
		rep.Services = append(rep.Services, s)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if rep.Services == nil {
		rep.Services = []hostService{}
	}

	// 3. Observation provenance breakdown.
	orows, err := db.QueryContext(ctx, `
SELECT COALESCE(ds.name, printf('source#%d', o.source_id)) AS src,
       count(*), max(o.observed_at)
FROM observations o
LEFT JOIN data_sources ds ON ds.id = o.source_id
WHERE o.asset_id = ?1
GROUP BY 1
ORDER BY 2 DESC`, rep.Asset.ID)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = orows.Close() }()
	for orows.Next() {
		var src, last string
		var n int64
		if err := orows.Scan(&src, &n, &last); err != nil {
			return nil, false, err
		}
		rep.Observations.BySource[src] = n
		rep.Observations.Total += n
		t := personalTSTime(last)
		if rep.Observations.LastObtain == nil || t.After(*rep.Observations.LastObtain) {
			rep.Observations.LastObtain = &t
		}
	}
	if err := orows.Err(); err != nil {
		return nil, false, err
	}

	return rep, true, nil
}

// personalTSTime parses a personal-engine TEXT timestamp (SQ-02: UTC RFC
// 3339 with six fractional digits; sqlite.ParseTS is the storage
// layer's own reader).  A value the storage layer did not write renders
// as the zero time instead of failing the whole read-only report.
func personalTSTime(s string) time.Time {
	t, err := sqlite.ParseTS(s)
	if err != nil {
		return time.Time{}
	}
	return t
}
