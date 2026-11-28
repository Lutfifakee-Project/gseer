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

// stats.go — the `gseer stats` informational view (R35 P5, R36 P3/P4):
// what the index holds, how fresh it is, and which sources are due for
// refresh.  Read-only over the personal store; every number is computed
// from the real rows (no cached counters to go stale).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func registerStatsCmd(root *cobra.Command) {
	stats := &cobra.Command{
		Use:   "stats",
		Short: "Index statistics and source freshness (read-only)",
		Args:  cobra.NoArgs,
		RunE:  runStatsCmd,
	}
	root.AddCommand(stats)
}

func runStatsCmd(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	_, closer, cfg, err := openRegistryStore(cmd)
	if err != nil {
		return err
	}
	defer closer()
	ctx := commandContext(cmd)
	db, err := sqlite.OpenReadOnly(cfg.Database.DSN)
	if err != nil {
		printf(out, "E_DB: %s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	defer func() { _ = db.Close() }()

	now := time.Now().UTC()
	q := func(query string, args ...any) (int64, error) {
		var n int64
		if err := db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			return 0, err
		}
		return n, nil
	}
	one := func(label string, n int64, err error) {
		if err != nil {
			printf(out, "  %-24s (unavailable: %v)\n", label, err)
			return
		}
		printf(out, "  %-24s %d\n", label, n)
	}

	printf(out, "index (personal store):\n")
	assets, aerr := q(`SELECT COUNT(*) FROM assets`)
	one("assets", assets, aerr)

	byKind := func(kind string) (int64, error) {
		return q(`SELECT COUNT(*) FROM assets WHERE kind = ?`, kind)
	}
	printf(out, "  by kind                 : ")
	kinds := []string{"domain", "hostname", "ip", "prefix"}
	var parts []string
	for _, k := range kinds {
		n, err := byKind(k)
		if err != nil {
			continue
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, n))
		}
	}
	if len(parts) == 0 {
		printf(out, "(none)\n")
	} else {
		printf(out, "%s\n", strings.Join(parts, " · "))
	}

	// Prefixes and origin ASNs from the BGP evidence (routeviews): the
	// prefix assets are recorded as facts with a routeviews evidence
	// object; count DISTINCT prefixes / origin ASNs defensively.
	prefixes, asnCount := statsRouteviews(db, ctx)
	one("announced prefixes", prefixes, nil)
	one("distinct origin ASNs", asnCount, nil)

	hostnames, herr := byKind("hostname")
	one("hostnames", hostnames, herr)
	domains, derr := byKind("domain")
	one("domains", domains, derr)

	dnsObs, dnsErr := q(`SELECT COUNT(*) FROM observations WHERE provenance = 'dns'`)
	one("dns records", dnsObs, dnsErr)
	httpObs, hErr := q(`SELECT COUNT(*) FROM observations WHERE provenance = 'scan-http'`)
	one("http observations", httpObs, hErr)
	tlsObs, tErr := q(`SELECT COUNT(*) FROM observations WHERE provenance = 'scan-tls'`)
	one("tls observations", tlsObs, tErr)
	totalObs, totErr := q(`SELECT COUNT(*) FROM observations`)
	one("observations", totalObs, totErr)
	fresh, fErr := q(`SELECT COUNT(*) FROM observations WHERE observed_at >= datetime('now', '-1 day')`)
	one("new (last 24h)", fresh, fErr)

	statsCoverage(db, ctx, out)

	printf(out, "\nsources:\n")
	printStatsSources(ctx, out, cfg.Database.DSN, now)
	return nil
}

// statsRouteviews counts distinct prefixes and origin ASNs from the
// routeviews evidence objects.  Malformed JSON rows are skipped (they
// are honest dead letters, not counters).
func statsRouteviews(db *sql.DB, ctx context.Context) (int64, int64) {
	prefixes := map[string]bool{}
	asns := map[int64]bool{}
	rows, err := db.QueryContext(ctx,
		`SELECT evidence FROM observations WHERE provenance = 'routeviews' AND evidence LIKE '%"prefix"%'`)
	if err != nil {
		return 0, 0
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		// Bounded per-row JSON read: only the two fields the counters
		// need (a full decode of 141k evidence blobs is wasted work).
		var m struct {
			Routeviews struct {
				Prefix    string `json:"prefix"`
				OriginASN int64  `json:"origin_asn"`
			} `json:"routeviews"`
		}
		if jsonUnmarshalStrict(raw, &m) != nil {
			continue
		}
		if m.Routeviews.Prefix != "" {
			prefixes[m.Routeviews.Prefix] = true
		}
		if m.Routeviews.OriginASN > 0 {
			asns[m.Routeviews.OriginASN] = true
		}
	}
	return int64(len(prefixes)), int64(len(asns))
}

// statsCoverage prints the asset_evidence coverage-class distribution
// (the P3/P4 coverage story over real indexed data).
func statsCoverage(db *sql.DB, ctx context.Context, out interface{ Write([]byte) (int, error) }) {
	rows, err := db.QueryContext(ctx,
		`SELECT coverage_class, COUNT(*) FROM asset_evidence GROUP BY coverage_class ORDER BY 2 DESC`)
	if err != nil {
		return // the coverage table needs 0006; an older store skips the section
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var class string
		var n int64
		if rows.Scan(&class, &n) != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %d", class, n))
	}
	if len(parts) > 0 {
		printf(out, "  %-24s %s\n", "coverage classes", strings.Join(parts, " · "))
	}
}

// jsonUnmarshalStrict decodes one evidence blob defensively (unknown
// fields allowed — evidence grows across versions; a malformed blob is
// a counter skip, never a crash).
func jsonUnmarshalStrict(raw string, v any) error {
	return json.Unmarshal([]byte(raw), v)
}

// printStatsSources reports every registered source's freshness and
// state (STALE / fresh / disabled / never run) from the job history.
func printStatsSources(ctx context.Context, out interface{ Write([]byte) (int, error) }, dsn string, now time.Time) {
	db, err := sqlite.OpenReadOnly(dsn)
	if err != nil {
		printf(out, "  (source health unavailable: %v)\n", err)
		return
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query("SELECT id, name, connector, config, enabled FROM data_sources ORDER BY name")
	if err != nil {
		printf(out, "  (source health unavailable: %v)\n", err)
		return
	}
	defer rows.Close()
	// P5 failures per source: the job history's failed runs, counted.
	failedBy := map[int64]int{}
	if frows, ferr := db.Query("SELECT source_id, COUNT(*) FROM collection_jobs WHERE status = 'failed' GROUP BY source_id"); ferr == nil {
		defer frows.Close()
		for frows.Next() {
			var sid int64
			var n int
			if frows.Scan(&sid, &n) == nil {
				failedBy[sid] = n
			}
		}
	}
	type srcRow struct {
		name, connector, state string
	}
	var list []srcRow
	for rows.Next() {
		var id int64
		var name, connector string
		var cfgRaw sql.NullString
		var enabled bool
		if rows.Scan(&id, &name, &connector, &cfgRaw, &enabled) != nil {
			continue
		}
		if !enabled {
			list = append(list, srcRow{name: name, connector: connector, state: "disabled"})
			continue
		}
		interval := scheduleIntervalFor(connector, []byte(cfgRaw.String))
		last, lerr := scheduleLastSuccess(ctx, db, id)
		switch {
		case lerr != nil || last.IsZero():
			list = append(list, srcRow{name: name, connector: connector, state: "never run (due)"})
		case now.Sub(last) >= interval:
			list = append(list, srcRow{name: name, connector: connector,
				state: fmt.Sprintf("STALE (due, %.1fx interval)", now.Sub(last).Hours()/interval.Hours())})
		default:
			list = append(list, srcRow{name: name, connector: connector,
				state: fmt.Sprintf("fresh (%.0f%% of interval)", now.Sub(last).Seconds()/interval.Seconds()*100)})
		}
		if n := failedBy[id]; n > 0 {
			list[len(list)-1].state += fmt.Sprintf(" · %d failed run(s)", n)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	for _, r := range list {
		printf(out, "  %-24s %-12s %s\n", r.name, r.connector, r.state)
	}
}
