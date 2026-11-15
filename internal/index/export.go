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

package index

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// export.go — the provider-side snapshot export (used by
// cmd/gseer-provider build): a populated personal-mode store becomes a
// self-contained snapshot file with the SAME schema.
//
// Rows are copied VERBATIM with their ids, timestamps, evidence, and
// provenance — the client's importer remaps ids and rewrites
// provenance on ITS side.  Runner-local state (collection jobs,
// checkpoints, dead letters, scopes, scan audits, leases,
// suppressions) is deliberately NOT exported: the shared index carries
// facts, not the provider's operational state.  data_sources IS
// exported because observations reference it (FK integrity) and the
// source names/terms are part of the provenance story.

// ExportSnapshot writes the snapshot file and returns the row counts
// the manifest must claim.
func ExportSnapshot(ctx context.Context, src *sqlite.Store, outPath string) (*Counts, error) {
	if _, err := os.Stat(outPath); err == nil {
		return nil, errf(CodeState, "the snapshot output path already exists",
			fmt.Sprintf("%s", outPath),
			"remove it or choose another --out path (a published snapshot is immutable; never overwrite)", nil)
	}
	dstRes, err := sqlite.Open(outPath)
	if err != nil {
		return nil, errf(CodeState, "cannot create the snapshot file", err.Error(), "", err)
	}
	defer func() { _ = dstRes.DB.Close() }()
	if _, err := sqlite.Migrate(ctx, dstRes.DB); err != nil {
		return nil, errf(CodeState, "cannot migrate the snapshot schema", err.Error(), "", err)
	}

	if err := copyTable(ctx, src.DB, dstRes.DB, "data_sources",
		"id, name, connector, terms_ref, config, enabled, created_at"); err != nil {
		return nil, err
	}
	if err := copyTable(ctx, src.DB, dstRes.DB, "assets",
		"id, kind, value, ip, domain, hostname, asn, asn_org, geo_country, geo_region, geo_city, sources, first_seen, last_seen, stale"); err != nil {
		return nil, err
	}
	if err := copyTable(ctx, src.DB, dstRes.DB, "services",
		"id, asset_id, port, transport, protocol, name, product, version, first_seen, last_seen, stale"); err != nil {
		return nil, err
	}
	if err := copyTable(ctx, src.DB, dstRes.DB, "observations",
		"id, source_id, asset_id, service_id, observed_at, payload_hash, source_cursor, provenance, evidence, created_at"); err != nil {
		return nil, err
	}

	got, err := snapshotCounts(ctx, dstRes.DB)
	if err != nil {
		return nil, errf(CodeIntegrity, "cannot count the exported rows", err.Error(), "", err)
	}
	// Sanity: the export must equal the source (the copy is total).
	want, err := snapshotCounts(ctx, src.DB)
	if err != nil {
		return nil, errf(CodeIntegrity, "cannot count the source rows", err.Error(), "", err)
	}
	if got != want {
		return nil, &Error{Code: CodeIntegrity,
			What: fmt.Sprintf("export count mismatch (assets %d→%d, services %d→%d, observations %d→%d)",
				want.Assets, got.Assets, want.Services, got.Services, want.Observations, got.Observations),
			Next: "refuse to publish; the export is incomplete"}
	}
	return &got, nil
}

// copyTable copies one table's full column set between the two SQLite
// databases with ids preserved.
func copyTable(ctx context.Context, src, dst *sql.DB, table, cols string) error {
	rows, err := src.QueryContext(ctx, `SELECT `+cols+` FROM `+table)
	if err != nil {
		return errf(CodeState, "cannot read "+table+" from the source store", err.Error(), "", err)
	}
	defer func() { _ = rows.Close() }()

	tx, err := dst.BeginTx(ctx, nil)
	if err != nil {
		return errf(CodeState, "cannot begin the "+table+" copy", err.Error(), "", err)
	}
	ncols := len(splitCols(cols))
	placeholders := "?"
	for i := 1; i < ncols; i++ {
		placeholders += ", ?"
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO `+table+` (`+cols+`) VALUES (`+placeholders+`)`)
	if err != nil {
		_ = tx.Rollback()
		return errf(CodeState, "cannot prepare the "+table+" copy", err.Error(), "", err)
	}
	defer func() { _ = stmt.Close() }()

	vals := make([]any, ncols)
	ptrs := make([]any, ncols)
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			_ = tx.Rollback()
			return errf(CodeState, "cannot scan a "+table+" row", err.Error(), "", err)
		}
		if _, err := stmt.ExecContext(ctx, vals...); err != nil {
			_ = tx.Rollback()
			return errf(CodeState, "cannot insert a "+table+" row", err.Error(), "", err)
		}
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return errf(CodeState, "cannot iterate "+table, err.Error(), "", err)
	}
	if err := tx.Commit(); err != nil {
		return errf(CodeState, "cannot commit the "+table+" copy", err.Error(), "", err)
	}
	return nil
}

func splitCols(cols string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(cols); i++ {
		if i == len(cols) || cols[i] == ',' {
			out = append(out, cols[start:i])
			start = i + 1
		}
	}
	return out
}
