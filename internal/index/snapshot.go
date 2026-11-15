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

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// snapshot.go — snapshot validation (trust-chain step 4).
//
// A downloaded snapshot is an untrusted SQLite file until it has passed
// every check here: SQLite integrity_check, the schema position (never
// NEWER than this build — the client cannot read columns it does not
// know), and the exact row counts the signed manifest claims.  The
// signature and checksum (steps 1/3) prove WHO built it and that the
// bytes arrived intact; this step proves the file IS what the manifest
// says it is.

// ValidateSnapshot opens the snapshot READ-ONLY and validates it
// against the manifest's counts and this build's schema head.
func ValidateSnapshot(ctx context.Context, path string, want Counts) error {
	db, err := sqlite.OpenReadOnly(path)
	if err != nil {
		return errf(CodeSchema, "cannot open the downloaded snapshot", err.Error(),
			"refuse the snapshot; the manifest is authoritative", err)
	}
	defer func() { _ = db.Close() }()

	// 1. SQLite integrity_check — a truncated/corrupt file refuses here.
	var ic string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&ic); err != nil {
		return errf(CodeIntegrity, "integrity_check could not run", err.Error(),
			"refuse the snapshot; do not install a file SQLite cannot read", err)
	}
	if ic != "ok" {
		return &Error{Code: CodeIntegrity, What: "the snapshot failed SQLite integrity_check",
			Why:  "integrity_check reported: " + ic,
			Next: "refuse the snapshot; the release artifact is corrupt or tampered with"}
	}

	// 2. Schema position — the snapshot must never be NEWER than this
	//    build (unknown columns); BEHIND is fine (migrations are
	//    additive and the importer only reads the base tables).
	st, err := sqlite.GetMigrationStatus(ctx, db)
	if err != nil {
		return errf(CodeSchema, "cannot read the snapshot's migration state", err.Error(),
			"refuse the snapshot; it is not a GSEER index file", err)
	}
	switch st.State {
	case sqlite.StateAhead:
		return &Error{
			Code: CodeSchema,
			What: fmt.Sprintf("the snapshot's schema (v%d) is NEWER than this build (v%d)", st.Version, st.Head),
			Why:  "an older client cannot correctly read a newer snapshot — the column set may differ",
			Next: "update gseer (gseer update --apply) and retry: gseer index update",
		}
	case sqlite.StateDirty:
		return &Error{Code: CodeSchema, What: "the snapshot's migration ledger is DIRTY",
			Next: "refuse the snapshot; a healthy provider never publishes one"}
	case sqlite.StateUninitialized:
		return &Error{Code: CodeSchema, What: "the snapshot carries no GSEER schema",
			Next: "refuse the snapshot; it is not a GSEER index file"}
	}

	// 3. Row counts vs the signed manifest.
	got, err := snapshotCounts(ctx, db)
	if err != nil {
		return errf(CodeIntegrity, "cannot count the snapshot rows", err.Error(),
			"refuse the snapshot", err)
	}
	if got != want {
		return &Error{
			Code: CodeIntegrity,
			What: fmt.Sprintf("snapshot row counts do not match the manifest (assets %d/%d, services %d/%d, observations %d/%d)",
				got.Assets, want.Assets, got.Services, want.Services, got.Observations, want.Observations),
			Why:  "the manifest is signed and authoritative; a mismatch means a tampered or mixed artifact",
			Next: "refuse the snapshot",
		}
	}
	return nil
}

// snapshotCounts counts the three base tables (plain COUNT(*) — the
// manifest counts refer to the base rows, not the search_index view).
func snapshotCounts(ctx context.Context, db *sql.DB) (Counts, error) {
	var got Counts
	for _, c := range []struct {
		table string
		dst   *int64
	}{
		{"assets", &got.Assets},
		{"services", &got.Services},
		{"observations", &got.Observations},
	} {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table).Scan(c.dst); err != nil {
			return Counts{}, fmt.Errorf("count %s: %w", c.table, err)
		}
	}
	return got, nil
}

// InspectSnapshot is the provider-side pre-publication self-check: it
// opens the snapshot READ-ONLY, runs integrity_check, and returns the
// row counts + schema head a manifest must claim.  cmd/gseer-provider
// manifest calls this so a broken snapshot can never reach the signing
// step.
func InspectSnapshot(ctx context.Context, path string) (*Counts, int, error) {
	db, err := sqlite.OpenReadOnly(path)
	if err != nil {
		return nil, 0, errf(CodeSchema, "cannot open the snapshot", err.Error(),
			"build the snapshot with gseer-provider build first", err)
	}
	defer func() { _ = db.Close() }()
	var ic string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&ic); err != nil || ic != "ok" {
		reason := ic
		if err != nil {
			reason = err.Error()
		}
		return nil, 0, &Error{Code: CodeIntegrity, What: "the snapshot failed SQLite integrity_check",
			Why:  "integrity_check reported: " + reason,
			Next: "rebuild the snapshot; never sign a corrupt artifact"}
	}
	got, err := snapshotCounts(ctx, db)
	if err != nil {
		return nil, 0, errf(CodeIntegrity, "cannot count the snapshot rows", err.Error(),
			"refuse: the file is not a GSEER snapshot", err)
	}
	st, err := sqlite.GetMigrationStatus(ctx, db)
	if err != nil {
		return nil, 0, errf(CodeSchema, "cannot read the snapshot's migration state", err.Error(), "", err)
	}
	if st.State == sqlite.StateAhead || st.State == sqlite.StateDirty || st.State == sqlite.StateUninitialized {
		if st.State == sqlite.StateAhead {
			return nil, 0, &Error{Code: CodeSchema,
				What: fmt.Sprintf("the snapshot's schema (v%d) is NEWER than this build (v%d)", st.Version, st.Head),
				Why:  "this provider build cannot correctly read a newer snapshot — the column set may differ",
				Next: "update the pipeline tooling and retry the restore; never restore a schema-ahead base",
			}
		}
		return nil, 0, &Error{Code: CodeSchema, What: "the snapshot's migration ledger is " + string(st.State),
			Next: "rebuild the snapshot from a healthy pipeline store"}
	}
	return &got, int(st.Version), nil
}
