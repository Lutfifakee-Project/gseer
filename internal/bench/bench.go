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

// Package bench — the reproducible performance benchmark harness (R140).
//
// `gseer bench run` measures a FIXED, versioned workload set against the
// current personal index through the SAME search service the CLI uses —
// never a special fast path.  Probe inputs are discovered from the index
// itself, deterministically, and recorded in the results file so a
// `compare` run can prove what it measured.  `gseer bench compare` gates
// a results file against a saved baseline: a workload whose p95 exceeds
// the baseline × tolerance is a REGRESSION (exit code 5, CI-able).
//
// The harness is strictly read-only: search never triggers scanning and
// the bench never writes user data.
package bench

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/relations"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
)

// BenchVersion versions the workload set itself: comparisons are only
// meaningful between results produced by the same workload version.
// bench-v3 (r23): hostname_prefix now uses the real wildcard operator
// (`*=`, OpMatch — the v2 `==`-with-star form matched nothing, a v2
// workload bug caught in R114 review), and adds tls_filter + ct_filter
// workloads — benchgen now generates TLS and CT evidence through the
// same generic projection the collectors use, so those searches have
// genuine data behind them.  v2 baselines fail closed (version
// mismatch) — re-baseline after upgrading.
const BenchVersion = "bench-v3"

// QueryTimeout bounds each measured query (p95 budget well above the
// 5s service default; a query that hits this is a failed sample).
const QueryTimeout = 10 * time.Second

// Workload is one named group of measurements.
type Workload struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // search | facets | relations
	Queries []string `json:"queries,omitempty"`
	Facets  []string `json:"facets,omitempty"`
}

// workloadSet is the FIXED workload definition (BenchVersion).  Every
// query is plain GQL through the standard search pipeline.
func workloadSet(p Probes) []Workload {
	ws := []Workload{
		{Name: "point_lookup", Kind: "search", Queries: []string{
			`ip == "` + p.IP1 + `"`,
			`ip == "` + p.IP2 + `"`,
		}},
		{Name: "service_filter", Kind: "search", Queries: []string{
			`port == 443 && protocol == "https"`,
			`port == 80`,
			`port == 22`,
		}},
		{Name: "asn_filter", Kind: "search", Queries: []string{
			fmt.Sprintf(`asn == %d`, p.ASN),
			`asn_org == "` + p.Org + `"`,
		}},
		{Name: "facets", Kind: "facets", Queries: []string{
			`port == 443`,
		}, Facets: []string{"port", "protocol"}},
		{Name: "relations", Kind: "relations"},
	}
	if hq := hostnameQueries(p.Host); len(hq) > 0 {
		ws = append(ws, Workload{Name: "hostname_prefix", Kind: "search", Queries: hq})
	}
	if p.TLSVersion != "" {
		ws = append(ws, Workload{Name: "tls_filter", Kind: "search", Queries: []string{
			`tls.version == "` + p.TLSVersion + `"`,
			`tls.cert_issuer_cn CONTAINS ` + `"` + firstWord(p.TLSIssuer) + `"`,
		}})
	}
	if p.CTType != "" {
		ws = append(ws, Workload{Name: "ct_filter", Kind: "search", Queries: []string{
			`ct.entry_type == "` + p.CTType + `"`,
			`ct.issuer CONTAINS "` + firstWord(p.CTIssuer) + `"`,
		}})
	}
	return ws
}

// firstWord returns the leading token of s (for issuer substring
// probes); empty-safe.
func firstWord(s string) string {
	for i, r := range s {
		if r == ' ' {
			return s[:i]
		}
	}
	return s
}

// Probes are the deterministic inputs discovered from the index.
type Probes struct {
	IP1 string `json:"ip1"`
	IP2 string `json:"ip2"`
	ASN int64  `json:"asn"`
	Org string `json:"org"`
	// Host is optional: corpora without hostname assets simply skip the
	// hostname_prefix workload (honest shape adaptation, not failure).
	Host string `json:"host,omitempty"`
	// TLS/CT probe values (bench-v3) are discovered from the corpus's
	// latest_tls/latest_ctlog projections; when either table is empty
	// the corresponding workload is skipped.
	TLSVersion string `json:"tls_version,omitempty"`
	TLSIssuer  string `json:"tls_issuer,omitempty"`
	CTType     string `json:"ct_type,omitempty"`
	CTIssuer   string `json:"ct_issuer,omitempty"`
}

// DiscoverProbes reads deterministic probe values from the index
// (ORDER BY id — stable for a given corpus).  Empty corpus → error.
func DiscoverProbes(db *sql.DB) (Probes, error) {
	p := Probes{}
	get := func(dst *string, q string) error {
		return db.QueryRow(q).Scan(dst)
	}
	if err := get(&p.IP1, `SELECT value FROM assets WHERE kind = 'ip' AND EXISTS (SELECT 1 FROM services s WHERE s.asset_id = assets.id) ORDER BY id LIMIT 1`); err != nil {
		return p, fmt.Errorf("no IP asset with services in this index — run gseer bench on a populated index")
	}
	if err := get(&p.IP2, `SELECT value FROM assets WHERE kind = 'ip' ORDER BY id DESC LIMIT 1`); err != nil {
		return p, err
	}
	var asn sql.NullInt64
	if err := db.QueryRow(`SELECT asn FROM assets WHERE asn IS NOT NULL AND asn > 0 ORDER BY id LIMIT 1`).Scan(&asn); err == nil {
		p.ASN = asn.Int64
	}
	_ = get(&p.Org, `SELECT asn_org FROM assets WHERE asn_org <> '' ORDER BY id LIMIT 1`)
	_ = get(&p.Host, `SELECT hostname FROM assets WHERE hostname IS NOT NULL AND hostname <> '' ORDER BY id LIMIT 1`)
	_ = get(&p.TLSVersion, `SELECT tls_version FROM latest_tls_t WHERE tls_version IS NOT NULL ORDER BY service_id LIMIT 1`)
	_ = get(&p.TLSIssuer, `SELECT cert_issuer_cn FROM latest_tls_t WHERE cert_issuer_cn IS NOT NULL ORDER BY service_id LIMIT 1`)
	_ = get(&p.CTType, `SELECT entry_type FROM latest_ctlog_t WHERE entry_type IS NOT NULL ORDER BY asset_id LIMIT 1`)
	_ = get(&p.CTIssuer, `SELECT issuer FROM latest_ctlog_t WHERE issuer IS NOT NULL ORDER BY asset_id LIMIT 1`)
	return p, nil
}

// hostnameQueries derives the hostname_prefix GQL queries from the probe
// hostname (corpus-agnostic): a NARROW wildcard prefix (index-served
// since migration 0015) and a domain-suffix enumeration (substring
// semantics — an honest scan-path baseline).
func hostnameQueries(host string) []string {
	if host == "" {
		return nil
	}
	dot := strings.Index(host, ".")
	var prefix, domain string
	if dot > 0 {
		prefix, domain = host[:dot], host[dot+1:]
	} else {
		prefix, domain = host, host
	}
	// bench-v3: `*=` (OpMatch) — the engine's real wildcard semantics.
	// The v2 form used `==` with star characters, which is literal
	// equality and matched nothing.
	return []string{
		`hostname *= "` + prefix + `*"`,
		`hostname *= "*.` + domain + `"`,
	}
}

// Sample is one measured query execution.
type Sample struct {
	Workload string    `json:"workload"`
	Query    string    `json:"query"`
	Ms       []float64 `json:"ms"`
}

// WorkloadStat is the aggregate reported for one workload.
type WorkloadStat struct {
	Name    string  `json:"name"`
	Samples int     `json:"samples"`
	P50     float64 `json:"p50_ms"`
	P95     float64 `json:"p95_ms"`
	P99     float64 `json:"p99_ms"`
	Max     float64 `json:"max_ms"`
}

// Results is one complete bench run (the compare payload).
type Results struct {
	BenchVersion string         `json:"bench_version"`
	CreatedAt    time.Time      `json:"created_at"`
	Runs         int            `json:"runs_per_query"`
	Probes       Probes         `json:"probes"`
	AssetCount   int64          `json:"asset_count"`
	DBBytes      int64          `json:"db_bytes"`
	Workloads    []WorkloadStat `json:"workloads"`
}

// Run executes the full workload set: 1 warmup + runs measured runs per
// query, aggregating percentiles per workload.  Every query runs through
// the production search service (no special-cased path).
func Run(ctx context.Context, db *sql.DB, svc *searchlite.Service, runs int) (*Results, []Sample, error) {
	if runs <= 0 {
		runs = 5
	}
	probes, err := DiscoverProbes(db)
	if err != nil {
		return nil, nil, err
	}
	var assetCount, dbBytes int64
	_ = db.QueryRow(`SELECT COUNT(*) FROM assets`).Scan(&assetCount)
	_ = db.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).Scan(&dbBytes)

	res := &Results{BenchVersion: BenchVersion, CreatedAt: time.Now().UTC(), Runs: runs, Probes: probes, AssetCount: assetCount, DBBytes: dbBytes}
	var samples []Sample
	for _, w := range workloadSet(probes) {
		var lat []float64
		switch w.Kind {
		case "search":
			for _, gql := range w.Queries {
				ms := benchSearch(ctx, svc, search.Query{GQL: gql, Limit: 20}, runs)
				samples = append(samples, Sample{Workload: w.Name, Query: gql, Ms: ms})
				lat = append(lat, ms...)
			}
		case "facets":
			for _, gql := range w.Queries {
				ms := benchFacets(ctx, svc, search.FacetsQuery{GQL: gql, Facets: w.Facets, MaxValues: 10}, runs)
				samples = append(samples, Sample{Workload: w.Name, Query: gql, Ms: ms})
				lat = append(lat, ms...)
			}
		case "relations":
			ms := benchRelations(ctx, db, probes.IP1, runs)
			samples = append(samples, Sample{Workload: w.Name, Query: "Explore(" + probes.IP1 + ")", Ms: ms})
			lat = append(lat, ms...)
		}
		if len(lat) == 0 {
			return nil, nil, fmt.Errorf("workload %q produced no samples", w.Name)
		}
		sort.Float64s(lat)
		res.Workloads = append(res.Workloads, WorkloadStat{
			Name: w.Name, Samples: len(lat),
			P50: percentile(lat, 50), P95: percentile(lat, 95), P99: percentile(lat, 99), Max: lat[len(lat)-1],
		})
	}
	return res, samples, nil
}

func benchSearch(ctx context.Context, svc *searchlite.Service, q search.Query, runs int) []float64 {
	out := make([]float64, 0, runs)
	for i := 0; i <= runs; i++ { // i==0 warmup
		c, cancel := context.WithTimeout(ctx, QueryTimeout)
		start := time.Now()
		_, err := svc.Search(c, q)
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		cancel()
		if err != nil && i > 0 {
			// A failing measured run is recorded at the timeout bound —
			// honest, and it WILL trip the regression gate.
			ms = float64(QueryTimeout.Milliseconds())
		}
		if i > 0 {
			out = append(out, ms)
		}
	}
	return out
}

func benchFacets(ctx context.Context, svc *searchlite.Service, q search.FacetsQuery, runs int) []float64 {
	out := make([]float64, 0, runs)
	for i := 0; i <= runs; i++ {
		c, cancel := context.WithTimeout(ctx, QueryTimeout)
		start := time.Now()
		_, err := svc.Facets(c, q)
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		cancel()
		if err != nil && i > 0 {
			ms = float64(QueryTimeout.Milliseconds())
		}
		if i > 0 {
			out = append(out, ms)
		}
	}
	return out
}

func benchRelations(ctx context.Context, db *sql.DB, probe string, runs int) []float64 {
	out := make([]float64, 0, runs)
	for i := 0; i <= runs; i++ {
		c, cancel := context.WithTimeout(ctx, QueryTimeout)
		start := time.Now()
		_, err := relations.Explore(c, db, probe, "", 10)
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		cancel()
		if err != nil && i > 0 {
			ms = float64(QueryTimeout.Milliseconds())
		}
		if i > 0 {
			out = append(out, ms)
		}
	}
	return out
}

// percentile of a sorted slice (nearest-rank).
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	idx := int(math.Ceil(p/100.0*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return math.Round(sorted[idx]*1000) / 1000
}

// Compare compares a fresh run against a baseline at the given tolerance
// (p95_new <= p95_base × tolerance).  Returns the per-workload report.
type CompareRow struct {
	Workload  string  `json:"workload"`
	BaseP95   float64 `json:"baseline_p95_ms"`
	NewP95    float64 `json:"new_p95_ms"`
	Ratio     float64 `json:"ratio"`
	Regressed bool    `json:"regressed"`
}

// MinAbsMsDefault is the absolute noise floor: a workload only counts
// as regressed when p95 exceeds BOTH the relative tolerance AND this
// many milliseconds above baseline.  Ratio-only gates are meaningless
// for sub-millisecond workloads (0.6→0.8 ms is 1.33x jitter, measured).
const MinAbsMsDefault = 25.0

func Compare(base, fresh *Results, tolerance, minAbsMs float64) ([]CompareRow, bool) {
	if tolerance <= 0 {
		tolerance = 1.2
	}
	if minAbsMs < 0 {
		minAbsMs = MinAbsMsDefault
	}
	rows := []CompareRow{}
	regressed := false
	for _, w := range fresh.Workloads {
		var bp float64 = -1
		for _, b := range base.Workloads {
			if b.Name == w.Name && base.BenchVersion == fresh.BenchVersion {
				bp = b.P95
			}
		}
		row := CompareRow{Workload: w.Name, NewP95: w.P95}
		if bp >= 0 {
			row.BaseP95 = bp
			row.Ratio = math.Round(w.P95/bp*1000) / 1000
			// Gate = relative ratio AND absolute noise floor (measured
			// reproducibility on the 1M corpus: real workloads vary ≤2%,
			// sub-ms probes jitter >40% — only the floor keeps them honest).
			row.Regressed = w.P95 > bp*tolerance && (w.P95-bp) > minAbsMs
		} else {
			// Missing workload or version mismatch: cannot verify — treat
			// as a regression (a gate must fail closed).
			row.Regressed = true
			row.Ratio = math.Inf(1)
		}
		if row.Regressed {
			regressed = true
		}
		rows = append(rows, row)
	}
	return rows, regressed
}

// LoadResults parses a saved results JSON file.
func LoadResults(data []byte) (*Results, error) {
	var r Results
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.BenchVersion == "" {
		return nil, fmt.Errorf("not a bench results file (missing bench_version)")
	}
	return &r, nil
}

// SaveResults serializes a results file.
func SaveResults(r *Results) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
