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

// coverage.go — `gseer coverage` (R67/R53): honest coverage metrics
// computed from the REAL indexed records.  Every number here is a
// COUNT/DISTINCT over the actual store — never collector totals, never
// claims about the Internet.  The output separates collected records
// (observations) from unique indexed assets and searchable state.

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// registerCoverageCmd attaches `gseer coverage`.
func registerCoverageCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Coverage report from the real indexed records (unique assets, families, freshness, sources)",
		Long: `Coverage report computed from the local index (R67).

Every number is measured over the real indexed records:
  - unique assets by kind (ip/domain/hostname),
  - IPv4 vs IPv6 (from the ip column),
  - distinct prefixes / origin ASNs / countries with evidence,
  - services, TLS certificates, CT records, DNS records (maintained
    projections),
  - observation freshness buckets, data age (oldest/newest), source
    breakdown with data states (active / stale / failed / not_available),
    and cross-source duplication (assets recorded by ≥2 distinct
    sources) plus per-country and per-ASN breakdowns — total collected
    records vs unique assets stay deliberately separated.

This is a report about YOUR index.  It makes no claim about Internet-wide
coverage.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != "personal" {
				printf(out, "E_PROFILE_UNSUPPORTED: gseer coverage runs on the personal (SQLite) store in this release\n")
				exitWith(ExitConfig)
				return nil
			}
			res, oerr := openPersonal(cfg)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()
			if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
				return merr
			}
			rep, err := computeCoverage(ctx, res.DB)
			if err != nil {
				return err
			}
			if jsonOutput() {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printf(out, "Coverage (unique indexed records — real counts, no claims about the Internet):\n")
			printf(out, "  unique assets            %d\n", rep.AssetsTotal)
			printf(out, "  by kind                  ip %d · domain %d · hostname %d\n", rep.AssetsIP, rep.AssetsDomain, rep.AssetsHostname)
			printf(out, "  IP families              IPv4 %d · IPv6 %d\n", rep.IPv4, rep.IPv6)
			printf(out, "  services                 %d\n", rep.Services)
			printf(out, "  distinct prefixes        %d\n", rep.Prefixes)
			printf(out, "  distinct origin ASNs     %d\n", rep.ASNs)
			printf(out, "  distinct countries       %d\n", rep.Countries)
			printf(out, "  certificates (latest)    %d\n", rep.Certs)
			printf(out, "  CT records (latest)      %d\n", rep.CTRecords)
			printf(out, "  DNS records (latest)     %d\n", rep.DNSRecords)
			printf(out, "observations (collected records, NOT unique assets):\n")
			printf(out, "  total                    %d\n", rep.Observations)
			printf(out, "  last 24h / 7d / 30d      %d / %d / %d\n", rep.Obs24h, rep.Obs7d, rep.Obs30d)
			printf(out, "change events:\n")
			printf(out, "  total                    %d\n", rep.Changes)
			printf(out, "  distinct ports           %d\n", rep.DistinctPorts)
			printf(out, "  distinct protocols       %d\n", rep.DistinctProtocols)
			printf(out, "  distinct ASN orgs        %d\n", rep.ASNOrgs)
			printf(out, "observations by asset kind:\n")
			kinds := []string{"ip", "domain", "hostname"}
			for _, k := range kinds {
				printf(out, "  %-24s %d\n", k, rep.ObsByAssetKind[k])
			}
			printf(out, "data age:\n")
			printf(out, "  oldest observation       %s\n", dash(rep.OldestObservedAt))
			printf(out, "  newest observation       %s\n", dash(rep.NewestObservedAt))
			printf(out, "sources:\n")
			for _, s := range rep.Sources {
				printf(out, "  %-24s observations %d · provenance %s\n", s.Name, s.Observations, s.Provenance)
			}
			printf(out, "source states (active = evidence ≤7d, stale = older, failed = last run errored, not_available = registered, no records):\n")
			for _, st := range rep.SourceStatuses {
				printf(out, "  %-24s %-13s observations %d · last %s · latest run %s\n",
					st.Name, st.Status, st.Observations, dash(st.LastObservedAt), dash(st.LatestJob))
			}
			printf(out, "cross-source duplication:\n")
			printf(out, "  assets seen by ≥2 sources %d\n", rep.DupAssets)
			for _, d := range rep.DupTop {
				printf(out, "  %-24s %s — %d distinct sources\n", d.Kind, d.Value, d.Sources)
			}
			if len(rep.TopCountries) > 0 {
				printf(out, "top countries (assets with country evidence):\n")
				for _, t := range rep.TopCountries {
					printf(out, "  %-24s %d\n", t.Label, t.Count)
				}
			}
			if len(rep.TopASNs) > 0 {
				printf(out, "top origin ASNs (assets with ASN evidence):\n")
				for _, t := range rep.TopASNs {
					printf(out, "  %-24s %d\n", t.Label, t.Count)
				}
			}
			printf(out, "\nLimitations: counts cover this index only. Historical raw observations\nmay have been pruned by retention (asset_changes events survive). Sources with\nnarrow scope produce narrow coverage — this is a property of the data, not of\nthe search engine.\n")
			return nil
		},
	}
	root.AddCommand(cmd)
}

// coverageReport is the measured shape (R67: separated metrics).
type coverageReport struct {
	AssetsTotal       int64            `json:"unique_assets"`
	AssetsIP          int64            `json:"assets_ip"`
	AssetsDomain      int64            `json:"assets_domain"`
	AssetsHostname    int64            `json:"assets_hostname"`
	IPv4              int64            `json:"ipv4_addresses"`
	IPv6              int64            `json:"ipv6_addresses"`
	Services          int64            `json:"services"`
	DistinctPorts     int64            `json:"distinct_ports"`
	DistinctProtocols int64            `json:"distinct_protocols"`
	Prefixes          int64            `json:"distinct_prefixes"`
	ASNs              int64            `json:"distinct_origin_asns"`
	ASNOrgs           int64            `json:"distinct_asn_orgs"`
	Countries         int64            `json:"distinct_countries"`
	Certs             int64            `json:"latest_certificates"`
	CTRecords         int64            `json:"latest_ct_records"`
	DNSRecords        int64            `json:"latest_dns_records"`
	Observations      int64            `json:"observations_total"`
	ObsByAssetKind    map[string]int64 `json:"observations_by_asset_kind"`
	OldestObservedAt  string           `json:"oldest_observed_at"`
	NewestObservedAt  string           `json:"newest_observed_at"`
	Obs24h            int64            `json:"observations_last_24h"`
	Obs7d             int64            `json:"observations_last_7d"`
	Obs30d            int64            `json:"observations_last_30d"`
	Changes           int64            `json:"change_events"`
	// Cross-source duplication (R68): assets recorded by more than one
	// distinct data source — the honest overlap signal between layers.
	DupAssets      int64                  `json:"assets_seen_by_multiple_sources"`
	DupTop         []coverageDupRow       `json:"most_cross_sourced_assets"`
	TopCountries   []coverageTopRow       `json:"top_countries"`
	TopASNs        []coverageTopRow       `json:"top_asns"`
	Sources        []coverageSource       `json:"sources"`
	SourceStatuses []coverageSourceStatus `json:"source_statuses"`
}

// coverageTopRow is one bucket of a top-N breakdown (label = country
// code or "ASN — org").
type coverageTopRow struct {
	Label string `json:"label"`
	Count int64  `json:"assets"`
}

// coverageDupRow is one asset seen by multiple distinct sources.
type coverageDupRow struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Sources int64  `json:"distinct_sources"`
}

// coverageSourceStatus classifies a registered source per R68's data
// states: active (fresh evidence ≤7d), stale (older evidence), failed
// (latest run failed, nothing recorded), not_available (registered,
// zero records).
type coverageSourceStatus struct {
	Name           string `json:"name"`
	Connector      string `json:"connector"`
	Status         string `json:"status"`
	Observations   int64  `json:"observations"`
	LastObservedAt string `json:"last_observed_at"`
	LatestJob      string `json:"latest_job_status"`
}

type coverageSource struct {
	Name         string `json:"name"`
	Provenance   string `json:"provenance"`
	Observations int64  `json:"observations"`
}

func computeCoverage(ctx context.Context, db *sql.DB) (*coverageReport, error) {
	r := &coverageReport{}
	count := func(query string, dest *int64) error {
		return db.QueryRowContext(ctx, query).Scan(dest)
	}
	if err := count(`SELECT COUNT(*) FROM assets`, &r.AssetsTotal); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM assets WHERE kind='ip'`, &r.AssetsIP); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM assets WHERE kind='domain'`, &r.AssetsDomain); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM assets WHERE kind='hostname'`, &r.AssetsHostname); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM assets WHERE kind='ip' AND ip LIKE '%:%'`, &r.IPv6); err != nil {
		return nil, err
	}
	r.IPv4 = r.AssetsIP - r.IPv6
	if err := count(`SELECT COUNT(*) FROM services`, &r.Services); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT prefix) FROM latest_ip2asn_t WHERE prefix IS NOT NULL`, &r.Prefixes); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT asn) FROM assets WHERE asn <> 0`, &r.ASNs); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT geo_country) FROM assets WHERE geo_country <> ''`, &r.Countries); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM latest_tls_t`, &r.Certs); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM latest_ctlog_t`, &r.CTRecords); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM latest_dns_t`, &r.DNSRecords); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM observations`, &r.Observations); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM observations WHERE observed_at >= datetime('now', '-1 day')`, &r.Obs24h); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM observations WHERE observed_at >= datetime('now', '-7 day')`, &r.Obs7d); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM observations WHERE observed_at >= datetime('now', '-30 day')`, &r.Obs30d); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM asset_changes`, &r.Changes); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT port) FROM services`, &r.DistinctPorts); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT protocol) FROM services`, &r.DistinctProtocols); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(DISTINCT asn_org) FROM assets WHERE asn_org <> ''`, &r.ASNOrgs); err != nil {
		return nil, err
	}
	if err := count(`SELECT COUNT(*) FROM (
			SELECT o.asset_id FROM observations o
			GROUP BY o.asset_id HAVING COUNT(DISTINCT o.source_id) >= 2)`, &r.DupAssets); err != nil {
		return nil, err
	}

	// Observations grouped by the recorded asset kind (collected-record
	// mix across the layers: ip / domain / hostname).
	krows, kerr := db.QueryContext(ctx, `
		SELECT a.kind, COUNT(*) FROM observations o
		JOIN assets a ON a.id = o.asset_id GROUP BY a.kind ORDER BY 2 DESC`)
	if kerr != nil {
		return nil, kerr
	}
	r.ObsByAssetKind = map[string]int64{}
	for krows.Next() {
		var kind string
		var n int64
		if err := krows.Scan(&kind, &n); err != nil {
			_ = krows.Close()
			return nil, err
		}
		r.ObsByAssetKind[kind] = n
	}
	if kerr := krows.Err(); kerr != nil {
		return nil, kerr
	}
	_ = krows.Close()

	// Overall data age (R68: record when the data was taken).
	var oldest, newest sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT MIN(observed_at), MAX(observed_at) FROM observations`).
		Scan(&oldest, &newest); err != nil {
		return nil, err
	}
	r.OldestObservedAt = nullTimeRFC3339(oldest)
	r.NewestObservedAt = nullTimeRFC3339(newest)

	// Top country / origin-ASN breakdowns (assets with evidence only —
	// enrichment columns are never invented beyond what a provider said).
	tcs, terr := topRows(ctx, db, `
		SELECT geo_country, COUNT(*) FROM assets
		WHERE geo_country <> '' GROUP BY geo_country ORDER BY 2 DESC LIMIT 10`)
	if terr != nil {
		return nil, terr
	}
	r.TopCountries = tcs
	tas, taerr := topRows(ctx, db, `
		SELECT COALESCE(asn_org, '') || ' (AS' || asn || ')', COUNT(*) FROM assets
		WHERE asn <> 0 GROUP BY asn, asn_org ORDER BY 2 DESC LIMIT 10`)
	if taerr != nil {
		return nil, taerr
	}
	r.TopASNs = tas

	// Most cross-sourced assets: the concrete overlap examples behind
	// the duplication count.
	drows, derr := db.QueryContext(ctx, `
		SELECT a.kind, a.value, COUNT(DISTINCT o.source_id) AS srcs
		FROM observations o JOIN assets a ON a.id = o.asset_id
		GROUP BY o.asset_id HAVING srcs >= 2 ORDER BY srcs DESC, a.value LIMIT 5`)
	if derr != nil {
		return nil, derr
	}
	for drows.Next() {
		var d coverageDupRow
		if err := drows.Scan(&d.Kind, &d.Value, &d.Sources); err != nil {
			_ = drows.Close()
			return nil, err
		}
		r.DupTop = append(r.DupTop, d)
	}
	if derr := drows.Err(); derr != nil {
		return nil, derr
	}
	_ = drows.Close()

	// Per-source states: counts, last observed, latest run status.
	jrows, jerr := db.QueryContext(ctx, `
		SELECT ds.name, COALESCE(ds.connector, ''), COUNT(o.id), MAX(o.observed_at),
			(SELECT status FROM collection_jobs cj WHERE cj.source_id = ds.id ORDER BY cj.id DESC LIMIT 1)
		FROM data_sources ds
		LEFT JOIN observations o ON o.source_id = ds.id
		GROUP BY ds.id ORDER BY COUNT(o.id) DESC`)
	if jerr != nil {
		return nil, jerr
	}
	defer jrows.Close()
	for jrows.Next() {
		var s coverageSource
		var st coverageSourceStatus
		var lastObs sql.NullString
		var latestJob sql.NullString
		if err := jrows.Scan(&s.Name, &s.Provenance, &s.Observations, &lastObs, &latestJob); err != nil {
			return nil, err
		}
		r.Sources = append(r.Sources, s)
		st.Name, st.Connector, st.Observations = s.Name, s.Provenance, s.Observations
		st.LastObservedAt = nullTimeRFC3339(lastObs)
		st.LatestJob = latestJob.String
		st.Status = classifySourceState(st.Observations, st.LastObservedAt, st.LatestJob)
		r.SourceStatuses = append(r.SourceStatuses, st)
	}
	return r, jrows.Err()
}

// dash renders empty strings as an honest dash.
func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// topRows runs a label/count query into a top-N slice.
func topRows(ctx context.Context, db *sql.DB, query string) ([]coverageTopRow, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []coverageTopRow
	for rows.Next() {
		var t coverageTopRow
		if err := rows.Scan(&t.Label, &t.Count); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// nullTimeRFC3339 normalizes a stored observed_at TEXT (RFC3339 or the
// sqlite job-bookkeeping format) into a stable RFC3339 string.
func nullTimeRFC3339(v sql.NullString) string {
	if !v.Valid || v.String == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999-07:00"} {
		if t, err := time.Parse(layout, v.String); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return v.String
}

// classifySourceState maps (records, last observed, latest run) onto the
// R68 data states, honestly.
func classifySourceState(observations int64, lastObservedRFC3339, latestJob string) string {
	if observations == 0 {
		if latestJob == "failed" {
			return "failed"
		}
		return "not_available"
	}
	if lastObservedRFC3339 == "" {
		return "not_available"
	}
	last, err := time.Parse(time.RFC3339, lastObservedRFC3339)
	if err != nil {
		return "not_available"
	}
	if time.Since(last) <= 7*24*time.Hour {
		return "active"
	}
	return "stale"
}
