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

// relations_cli.go — `gseer relations` (R76/R77): evidence-based
// infrastructure relationship discovery around one asset.  Strictly
// read-only (SELECT on the maintained projections); search ≠ scan is
// untouched — no network contact happens here.

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"

	"github.com/Lutfifakee-Project/gseer/internal/gql/parser"
	"github.com/Lutfifakee-Project/gseer/internal/gql/validator"
	"github.com/Lutfifakee-Project/gseer/internal/relations"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// registerRelationsCmd attaches `gseer relations`.
func registerRelationsCmd(root *cobra.Command) {
	var (
		fKind   string
		fLimit  int
		fFormat string
	)
	cmd := &cobra.Command{
		Use:   "relations <asset-value>",
		Short: "Evidence-based infrastructure relationships around one asset (R76/R77)",
		Long: `Discover infrastructure relationships from collected evidence (R76/R77).

Every edge comes from a maintained evidence projection and carries the
observation timestamp and source it was derived from — nothing is inferred
beyond what your collectors actually recorded:

  dns_resolves_to    hostname/domain → its recorded A/AAAA/CNAME/MX answers
  dns_reverse        IP ← other names whose DNS record mentions that IP
  asn_origin         IP → ASN / organization / prefix attribution
  prefix_peer        IP ↔ other assets announced under the same prefix
  cert_ct            domain/hostname → its CT-log certificate
  cert_ct_shared     domain ↔ other names on the same CT leaf certificate
  cert_tls           service → its TLS certificate (subject/serial/version)
  cert_tls_shared    service ↔ SAN names of the same TLS certificate
  same_org           asset ↔ other assets under the same ASN organization
  service            asset → its services (port/protocol/product)
  technology         service → fingerprinted technologies

Traversal is SQL over the maintained projections — no separate graph store
(edges exist only where evidence exists).  Read-only: this never contacts
the network.` + "\n\nExamples:\n" + `
  gseer relations example.org
  gseer relations 203.0.113.7 --kind cert_tls_shared
  gseer relations example.org --format json`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if fKind != "" && !validKind(fKind) {
				printf(out, "E_RELATIONS_KIND: unknown kind %q\nSupported: %s\n", fKind, strings.Join(relations.Kinds(), ", "))
				exitWith(ExitInvalidInput)
				return nil
			}
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != config.ProfilePersonal {
				return runRelationsSelfHosted(out, cfg, args[0], fKind, fLimit, fFormat)
			}
			res, oerr := openPersonal(cfg)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()
			if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
				return merr
			}
			rels, err := relations.Explore(ctx, res.DB, args[0], fKind, fLimit)
			if err != nil {
				printf(out, "E_RELATIONS: %s\n", err.Error())
				exitWith(ExitInvalidInput)
				return nil
			}
			return renderRelations(out, args[0], rels, fFormat)
		},
	}
	cmd.Flags().StringVar(&fKind, "kind", "", "restrict to one relation kind (see help)")
	cmd.Flags().IntVar(&fLimit, "limit", 10, "per-kind fanout cap")
	cmd.Flags().StringVar(&fFormat, "format", "", "output: table|json|csv")
	root.AddCommand(cmd)
}

// renderRelations writes the relation edges (shared by the personal and
// self-hosted paths — identical output contract, PG parity).
func renderRelations(out io.Writer, value string, rels []relations.Relation, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"asset": value, "count": len(rels), "relations": rels})
	case "csv":
		w := csv.NewWriter(out)
		defer w.Flush()
		_ = w.Write([]string{"kind", "from", "to", "detail", "observed_at", "source"})
		for _, r := range rels {
			_ = w.Write([]string{r.Kind, r.From, r.To, r.Detail, r.ObservedAt, r.Source})
		}
		return nil
	}
	if len(rels) == 0 {
		printf(out, "No evidence-based relations found for %q in this index.\n"+
			"Relations exist only where collectors recorded DNS/IP2ASN/CT/TLS/service/fingerprint evidence.\n", value)
		return nil
	}
	printf(out, "%d evidence-based relation(s) for %s:\n", len(rels), value)
	cur := ""
	for _, r := range rels {
		if r.Kind != cur {
			cur = r.Kind
			printf(out, "\n  %s\n", cur)
		}
		printf(out, "    → %-40s %-24s observed %s  (%s)\n", r.To, r.Detail, r.ObservedAt, r.Source)
	}
	printf(out, "\nAll edges carry provenance (observed_at + source). Nothing here is inferred.\n")
	return nil
}

func validKind(k string) bool {
	for _, vk := range relations.Kinds() {
		if vk == k {
			return true
		}
	}
	return false
}

// registerFieldsCmd attaches `gseer fields` (R79): the searchable field
// registry, straight from the live registry — no invented fields.
func registerFieldsCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "fields",
		Short: "List every searchable field with type and operators (from the live registry)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			rows := validator.FieldSummaries()
			printf(out, "Searchable fields (%d) — GQL: field OP value; combine with && || ! ( ... )\n", len(rows))
			for _, r := range rows {
				alias := ""
				if len(r.Aliases) > 0 {
					alias = "  (alias: " + strings.Join(r.Aliases, ", ") + ")"
				}
				printf(out, "  %-24s %-6s %-42s %s%s\n", r.Canonical, r.Type, strings.Join(r.Ops, " "), "", alias)
			}
			printf(out, "\nEvery row above is the LIVE registry the validator enforces — try: gseer search '<gql>' --validate\nExamples: gseer examples\n")
			return nil
		},
	}
	root.AddCommand(cmd)
}

// registerExamplesCmd attaches `gseer examples` (R79): runnable query
// examples that all parse against the real registry.
func registerExamplesCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "examples",
		Short: "Runnable GQL query examples (all validated against the registry)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			for i, ex := range queryExamples() {
				printf(out, "%2d. %s\n     %s\n", i+1, ex.gql, ex.desc)
			}
			return nil
		},
	}
	root.AddCommand(cmd)
}

type example struct {
	gql, desc string
}

// queryExamples — every entry is exercised by the E2E log; they are the
// same shapes the planner supports (no invented syntax).
func queryExamples() []example {
	return []example{
		{`port == 443 && protocol == "https"`, "all HTTPS services on 443"},
		{`ip ^= "203.0.113."`, "every asset in the 203.0.113.0/24 range (prefix match)"},
		{`asn == 13335 && country == "US"`, "Cloudflare AS13335 assets with US geo evidence"},
		{`asn_org *= "cloudflare"`, "substring match on the ASN organization"},
		{`http_server *= "nginx" && http_status == 200`, "nginx servers answering 200"},
		{`tls_version == "TLSv1.3"`, "services where TLS 1.3 was observed"},
		{`cert_subject_cn == "example.org"`, "services whose certificate subject is example.org"},
		{`dns_record *= "example"`, "assets whose latest DNS record mentions 'example'"},
		{`ct_subject_cn != ""`, "assets with CT-log certificate evidence"},
		{`technology *= "wordpress"`, "assets fingerprinted as WordPress"},
		{`provenance == "passive"`, "only passively collected observations"},
		{`last_seen >= "2026-11-01" && stale == false`, "freshly-seen, non-stale assets"},
	}
}

// registerSelfcheckCmd attaches `gseer selfcheck` (R96): continuous
// validation of core invariants on the live index.
func registerSelfcheckCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "selfcheck",
		Short: "Validate core invariants of the local index (R96 continuous validation)",
		Long: `Run invariant checks against the personal index (R96).

Checks (each reports PASS/FAIL with measured counts, never assumptions):
  schema        migrations at head
  integrity     observation log: provenance + observed_at present on every row
  consistency   every asset referenced by observations exists; services link to assets
  projections   latest_* row counts are <= their source counts (maintenance holds)
  changes       asset_changes reference existing assets; detect marker sane
  presets       saved presets still parse against the current registry
  performance   basic planner stats (rows/idx) for the hot queries

Read-only: nothing is modified.  Exit code 0 = all checks passed.` + "\n\nExample:\n  gseer selfcheck",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != config.ProfilePersonal {
				printf(out, "Selfcheck (self-hosted PostgreSQL) — invariant checks (R96):\n")
				return runSelfcheckSelfHosted(out, cfg)
			}
			res, oerr := openPersonal(cfg)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()
			if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
				return merr
			}
			failed := 0
			check := func(name string, ok bool, detail string) {
				status := "PASS"
				if !ok {
					status = "FAIL"
					failed++
				}
				printf(out, "  [%s] %-12s %s\n", status, name, detail)
			}
			// schema — same backend-aware source as `gseer doctor` (the
			// embedded migration registry, never a hardcoded literal)
			if st, merr := sqlite.GetMigrationStatus(ctx, res.DB); merr != nil {
				check("schema", false, fmt.Sprintf("migrations: cannot read the migration state: %v", merr))
			} else {
				check("schema", st.State == sqlite.StateAtHead, fmt.Sprintf("migrations at v%d (head v%d)", st.Version, st.Head))
			}
			// integrity
			var bad int
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations WHERE provenance = '' OR observed_at = ''`).Scan(&bad)
			check("integrity", bad == 0, fmt.Sprintf("%d observation(s) missing provenance/observed_at", bad))
			// consistency: dangling references
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations o LEFT JOIN assets a ON a.id = o.asset_id WHERE o.asset_id IS NOT NULL AND a.id IS NULL`).Scan(&bad)
			var badSvc int
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM services s LEFT JOIN assets a ON a.id = s.asset_id WHERE a.id IS NULL`).Scan(&badSvc)
			check("consistency", bad == 0 && badSvc == 0, fmt.Sprintf("%d dangling obs · %d dangling services", bad, badSvc))
			// projections: maintained tables hold ONE row per source entity
			var dupes int
			_ = res.DB.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM latest_dns_t) - (SELECT COUNT(DISTINCT asset_id) FROM latest_dns_t)
				+ (SELECT COUNT(*) FROM latest_ip2asn_t) - (SELECT COUNT(DISTINCT asset_id) FROM latest_ip2asn_t)
				+ (SELECT COUNT(*) FROM latest_tls_t) - (SELECT COUNT(DISTINCT service_id) FROM latest_tls_t)`).Scan(&dupes)
			check("projections", dupes == 0, fmt.Sprintf("%d duplicate projection rows", dupes))
			// changes
			var orphan int
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_changes c LEFT JOIN assets a ON a.id = c.asset_id WHERE a.id IS NULL`).Scan(&orphan)
			var seen, totalObs int
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM detect_seen`).Scan(&seen)
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&totalObs)
			markerOK := seen <= totalObs
			check("changes", orphan == 0 && markerOK, fmt.Sprintf("%d orphan events · detect marker %d/%d obs", orphan, seen, totalObs))
			// presets re-parse
			presetFail := checkPresets(ctx, res.DB)
			check("presets", presetFail == 0, fmt.Sprintf("%d preset(s) fail validation", presetFail))
			if failed > 0 {
				printf(out, "\n%d check(s) FAILED. Recovery: see RECOVERY.md; start with gseer changes detect --full and gseer db backup.\n", failed)
				exitWith(ExitUnavailable)
				return nil
			}
			printf(out, "\nAll invariant checks passed.\n")
			return nil
		},
	}
	root.AddCommand(cmd)
}

// checkPresets re-parses every saved preset with the live parser.
func checkPresets(ctx context.Context, db *sql.DB) int {
	rows, err := db.QueryContext(ctx, `SELECT gql FROM search_presets`)
	if err != nil {
		return 1
	}
	defer rows.Close()
	fails := 0
	for rows.Next() {
		var gql string
		if err := rows.Scan(&gql); err != nil {
			return 1
		}
		tree, perr := parser.Parse(gql)
		if perr != nil {
			fails++
			continue
		}
		if _, verr := validator.Validate(tree); verr != nil {
			fails++
		}
	}
	return fails
}

// registerMaintenanceCmd wires `gseer db maintenance` (R81).
func newDBMaintenanceCmd() *cobra.Command {
	var fVacuum bool
	cmd := &cobra.Command{
		Use:   "maintenance",
		Short: "Dataset maintenance: freshness classification, marker verification, ANALYZE (--vacuum optional)",
		Long: `Safe, transparent maintenance over the personal index (R81).

  freshness   classify observations per source: fresh (24h) / recent (7d) / stale (30d+) / cold (older)
  markers     verify the change-detection processed set against the observation log
  analyze     refresh SQLite query-planner statistics (always safe)
  vacuum      optional full VACUUM (reclaims space; needs ~2× DB free space; run OFFLINE)

Nothing is deleted here — retention is the explicit, dry-run-default
command (gseer db retention).  This command never destroys valid data.` + "\n\nExamples:\n" + `
  gseer db maintenance
  gseer db maintenance --vacuum`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != config.ProfilePersonal {
				return runMaintenanceSelfHosted(out, cfg, fVacuum)
			}
			res, oerr := sqlite.Open(cfg.Database.DSN)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()

			rows, err := res.DB.QueryContext(ctx, `
				SELECT COALESCE(ds.name, 'unknown'),
				       SUM(CASE WHEN o.observed_at >= datetime('now', '-1 day') THEN 1 ELSE 0 END),
				       SUM(CASE WHEN o.observed_at >= datetime('now', '-7 day') THEN 1 ELSE 0 END),
				       SUM(CASE WHEN o.observed_at <  datetime('now', '-30 day') THEN 1 ELSE 0 END),
				       COUNT(*)
				FROM observations o JOIN data_sources ds ON ds.id = o.source_id
				GROUP BY ds.id ORDER BY COUNT(*) DESC`)
			if err != nil {
				return err
			}
			printf(out, "Dataset freshness by source (transparent counts — nothing is deleted):\n")
			printf(out, "  %-26s %8s %8s %8s %8s\n", "source", "24h", "7d", ">30d", "total")
			for rows.Next() {
				var name string
				var d, w, old, total int64
				if err := rows.Scan(&name, &d, &w, &old, &total); err != nil {
					rows.Close()
					return err
				}
				printf(out, "  %-26s %8d %8d %8d %8d\n", name, d, w, old, total)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			var seen, totalObs int
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM detect_seen`).Scan(&seen)
			_ = res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&totalObs)
			printf(out, "Change-detection markers: %d processed / %d observations", seen, totalObs)
			if seen < totalObs {
				printf(out, "  → run gseer changes detect to process the remaining %d\n", totalObs-seen)
			} else {
				printf(out, "  → up to date\n")
			}
			if _, err := res.DB.ExecContext(ctx, `ANALYZE`); err != nil {
				return err
			}
			printf(out, "[ ok  ] query-planner statistics refreshed (ANALYZE).\n")
			if fVacuum {
				if _, err := res.DB.ExecContext(ctx, `VACUUM`); err != nil {
					return err
				}
				printf(out, "[ ok  ] VACUUM complete — database file compacted.\n")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fVacuum, "vacuum", false, "also run VACUUM (offline compaction; takes space and time)")
	return cmd
}
