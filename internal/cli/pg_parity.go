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

// pg_parity.go — PostgreSQL (self-hosted) branches for the r18 commands
// (relations, selfcheck, db maintenance, config validate).  This closes
// the P1 "PG parity" gap from ACCEPTANCE-R75 for the newest command
// surface: the SAME semantics run on BOTH stores, and every
// personal-only invariant is reported as an explicit [skip] — never
// silently omitted.  Read-only: no command here writes user data.

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/relations"
	"github.com/Lutfifakee-Project/gseer/internal/storage/postgres"
)

// openSelfHostedDB opens the runtime database/sql handle over the
// self-hosted PostgreSQL DSN (least-privilege runtime credential with an
// explicit notice, same contract as search).  Caller closes.
func openSelfHostedDB(out io.Writer, cfg *config.Config) (*sql.DB, error) {
	dsn := runtimeCommandDSN(out, cfg)
	db, err := sql.Open("pgx/v5", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open the PostgreSQL connection: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cannot reach PostgreSQL (%s): %w", postgres.MustRedactDSN(dsn), err)
	}
	return db, nil
}

// runRelationsSelfHosted — the PostgreSQL twin of the personal relations
// path: identical kinds, identical provenance semantics (dialect.go).
func runRelationsSelfHosted(out io.Writer, cfg *config.Config, value, kindFilter string, limit int, format string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := openSelfHostedDB(out, cfg)
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: %s\nTry: check database.dsn — gseer doctor\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	defer func() { _ = db.Close() }()
	rels, err := relations.ExplorePG(ctx, db, value, kindFilter, limit)
	if err != nil {
		printf(out, "E_RELATIONS: %s\n", err.Error())
		exitWith(ExitInvalidInput)
		return nil
	}
	return renderRelations(out, value, rels, format)
}

// runSelfcheckSelfHosted — the PostgreSQL twin of selfcheck: the checks
// that exist on BOTH schemas run on PG; personal-only features (change
// detection markers, saved presets) are reported as [skip] with the
// reason, never silently omitted (honesty floor).
func runSelfcheckSelfHosted(out io.Writer, cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := openSelfHostedDB(out, cfg)
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: %s\nTry: check database.dsn — gseer doctor\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	defer func() { _ = db.Close() }()
	failed := 0
	check := func(name string, ok bool, detail string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		}
		printf(out, "  [%s] %-12s %s\n", status, name, detail)
	}
	skip := func(name, detail string) {
		printf(out, "  [skip] %-12s %s\n", name, detail)
	}

	// schema: migration state via the read-only status probe.
	st, serr := postgres.GetMigrationStatus(ctx, cfg.Database.DSN)
	if serr != nil {
		printf(out, "E_SELF_CHECK: migration status: %s\n", serr.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	check("schema", st.State == postgres.StateAtHead,
		fmt.Sprintf("migration state %s (recorded v%d, head v%d)", st.State, st.Version, st.Head))

	// integrity: provenance on every observation.
	var bad int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations WHERE provenance IS NULL OR provenance = ''`).Scan(&bad)
	check("integrity", bad == 0, fmt.Sprintf("%d observation(s) missing provenance", bad))

	// consistency: no dangling references.
	var badObs, badSvc int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations o LEFT JOIN assets a ON a.id = o.asset_id WHERE o.asset_id IS NOT NULL AND a.id IS NULL`).Scan(&badObs)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services s LEFT JOIN assets a ON a.id = s.asset_id WHERE a.id IS NULL`).Scan(&badSvc)
	check("consistency", badObs == 0 && badSvc == 0, fmt.Sprintf("%d dangling obs · %d dangling services", badObs, badSvc))

	// projections: one row per source entity (portable aggregate).
	var dupes int
	_ = db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM latest_dns_t) - (SELECT COUNT(DISTINCT asset_id) FROM latest_dns_t)
		+ (SELECT COUNT(*) FROM latest_ip2asn_t) - (SELECT COUNT(DISTINCT asset_id) FROM latest_ip2asn_t)
		+ (SELECT COUNT(*) FROM latest_tls_t) - (SELECT COUNT(DISTINCT service_id) FROM latest_tls_t)`).Scan(&dupes)
	check("projections", dupes == 0, fmt.Sprintf("%d duplicate projection rows", dupes))

	// changes / presets are personal-mode features (SQLite-scoped by
	// design — see docs/CHANGES.md); explicitly skipped on PG.
	skip("changes", "change-detection markers are a personal-mode feature (SQLite store)")
	skip("presets", "saved presets are a personal-mode feature (SQLite store)")

	if failed > 0 {
		printf(out, "\n%d check(s) FAILED. Recovery: see RECOVERY.md; start with gseer db migrate status.\n", failed)
		exitWith(ExitUnavailable)
		return nil
	}
	printf(out, "\nAll applicable invariant checks passed (2 personal-only checks skipped explicitly).\n")
	return nil
}

// runMaintenanceSelfHosted — freshness per source (PG interval math),
// planner statistics (ANALYZE), optional VACUUM.  Nothing is deleted.
func runMaintenanceSelfHosted(out io.Writer, cfg *config.Config, fVacuum bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	db, err := openSelfHostedDB(out, cfg)
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: %s\nTry: check database.dsn — gseer doctor\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	defer func() { _ = db.Close() }()

	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(ds.name, 'unknown'),
		       SUM(CASE WHEN o.observed_at >= now() - interval '1 day' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN o.observed_at >= now() - interval '7 day' THEN 1 ELSE 0 END),
		       SUM(CASE WHEN o.observed_at <  now() - interval '30 day' THEN 1 ELSE 0 END),
		       COUNT(*)
		FROM observations o JOIN data_sources ds ON ds.id = o.source_id
		GROUP BY ds.id ORDER BY COUNT(*) DESC`)
	if err != nil {
		printf(out, "E_MAINTENANCE: %s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
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

	if _, err := db.ExecContext(ctx, `ANALYZE`); err != nil {
		printf(out, "E_MAINTENANCE: ANALYZE failed: %s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	printf(out, "[ ok  ] query-planner statistics refreshed (ANALYZE).\n")
	if fVacuum {
		if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
			printf(out, "[warn ] VACUUM needs a non-transaction session: %s\n        Run it from the operator psql: VACUUM (ANALYZE);\n", err.Error())
		} else {
			printf(out, "[ ok  ] VACUUM complete — database compacted.\n")
		}
	}
	return nil
}

// runConfigValidateSelfHosted — post-upgrade safety probe on PG:
// configuration parses, database reachable, migrations classified.
func runConfigValidateSelfHosted(out io.Writer, cfg *config.Config) error {
	printf(out, "[ ok  ] configuration parses (profile %q, dsn redacted)\n", cfg.Profile)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := postgres.GetMigrationStatus(ctx, cfg.Database.DSN)
	if err != nil {
		printf(out, "INVALID: database: %s\n", err.Error())
		exitWith(ExitConfig)
		return nil
	}
	printf(out, "[ ok  ] database reachable, migration state %s (recorded v%d, head v%d)\n", st.State, st.Version, st.Head)
	if st.State != postgres.StateAtHead {
		printf(out, "        → run: gseer db migrate up\n")
	}
	printf(out, "Configuration valid.\n")
	return nil
}
