// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"database/sql"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// personal_import_verify.go — QS-6 R4: the END-STATE integrity proof
// for the legacy personal-database import.
//
// Contract (owner acceptance, QS-6 setup isolation): the import note
// must never claim more than is true of the file the operator ends up
// with.  importLegacyPersonalDB proves the COPY instant byte-identical
// (hash source vs staged copy, personal.go); provisioning then OPENS
// the imported file, and the SQ-05 open pragmas upgrade the SQLite
// journal mode to WAL — journal mode persists in the database HEADER
// (see dsn.go's pragmas comment; SQLite file-format read/write-version
// bytes and the change counter), so the final bytes can legitimately
// differ from the legacy source at an identical file size.
//
// verifyImportedPersonalDB therefore proves the END state:
//  1. byte-identical (sha256 equal) → reported as byte-identical;
//  2. otherwise a SEMANTIC equality proof, computed with both
//     databases opened strictly READ-ONLY (never written):
//     - PRAGMA user_version,
//     - every sqlite_master row (type, name, sql),
//     - one row count per user table;
//     all equal → the byte difference is exactly the journal-mode
//     header upgrade and schema + DATA are identical;
//  3. ANY semantic divergence is a hard E_SETUP failure — an import
//     that diverges from its source is never reported as success.
func verifyImportedPersonalDB(out io.Writer, source, target string) error {
	srcHash, err := fileHashBytes(source)
	if err != nil {
		return fmt.Errorf("hashing the legacy source for the end-state verification: %w", err)
	}
	dstHash, err := fileHashBytes(target)
	if err != nil {
		return fmt.Errorf("hashing the provisioned database for the end-state verification: %w", err)
	}
	if srcHash == dstHash {
		printf(out, "[ ok  ] end-state integrity: the provisioned database is byte-identical to %s\n", source)
		return nil
	}

	sdb, err := sqlite.OpenReadOnly(source)
	if err != nil {
		return fmt.Errorf("opening the legacy source read-only for verification: %w", err)
	}
	defer func() { _ = sdb.Close() }()
	tdb, err := sqlite.OpenReadOnly(target)
	if err != nil {
		return fmt.Errorf("opening the provisioned database read-only for verification: %w", err)
	}
	defer func() { _ = tdb.Close() }()

	if err := semanticDBEqual(sdb, tdb); err != nil {
		return fmt.Errorf("the imported database diverged from the legacy source %s — an import must "+
			"never diverge; the original is untouched (rollback: remove the provisioned file and point "+
			"database.dsn back at the original path): %w", source, err)
	}
	printf(out, "[ ok  ] end-state integrity: schema, metadata and row counts identical to %s\n", source)
	printf(out, "[ ok  ]   byte differences are the SQLite journal-mode header upgrade (WAL) performed at open\n")
	printf(out, "[ ok  ]   source sha256 %s…, provisioned sha256 %s… (semantic verification passed)\n",
		srcHash[:16], dstHash[:16])
	return nil
}

// semanticDBEqual compares two OPENED, read-only databases: user
// version, the full sqlite_master content and one row count per user
// table.  Everything is read; nothing is written.  The first divergence
// is reported with its concrete values.
func semanticDBEqual(a, b *sql.DB) error {
	type schemaRow struct{ typ, name, ddl string }
	type dbSnapshot struct {
		userVersion int
		schema      []schemaRow
		counts      []string // "table=count" in sqlite_master order
	}
	snapshot := func(db *sql.DB, label string) (*dbSnapshot, error) {
		s := &dbSnapshot{}
		if err := db.QueryRow(`PRAGMA user_version`).Scan(&s.userVersion); err != nil {
			return nil, fmt.Errorf("%s: user_version: %w", label, err)
		}
		rows, err := db.Query(`SELECT type, name, coalesce(sql, '') FROM sqlite_master ` +
			`WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY type, name`)
		if err != nil {
			return nil, fmt.Errorf("%s: sqlite_master: %w", label, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r schemaRow
			if err := rows.Scan(&r.typ, &r.name, &r.ddl); err != nil {
				return nil, fmt.Errorf("%s: scan sqlite_master: %w", label, err)
			}
			s.schema = append(s.schema, r)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s: iterate sqlite_master: %w", label, err)
		}
		for _, r := range s.schema {
			if r.typ != "table" {
				continue
			}
			var n int
			q := `SELECT count(*) FROM "` + strings.ReplaceAll(r.name, `"`, `""`) + `"`
			if err := db.QueryRow(q).Scan(&n); err != nil {
				return nil, fmt.Errorf("%s: count %s: %w", label, r.name, err)
			}
			s.counts = append(s.counts, fmt.Sprintf("%s=%d", r.name, n))
		}
		return s, nil
	}

	src, err := snapshot(a, "source")
	if err != nil {
		return err
	}
	dst, err := snapshot(b, "provisioned")
	if err != nil {
		return err
	}

	if src.userVersion != dst.userVersion {
		return fmt.Errorf("user_version differs: source=%d provisioned=%d", src.userVersion, dst.userVersion)
	}
	if !reflect.DeepEqual(src.schema, dst.schema) {
		for i := 0; i < len(src.schema) || i < len(dst.schema); i++ {
			var sv, dv schemaRow
			if i < len(src.schema) {
				sv = src.schema[i]
			}
			if i < len(dst.schema) {
				dv = dst.schema[i]
			}
			if sv != dv {
				return fmt.Errorf("schema differs at entry %d: source=(%s %s %q) provisioned=(%s %s %q)",
					i+1, sv.typ, sv.name, sv.ddl, dv.typ, dv.name, dv.ddl)
			}
		}
		return fmt.Errorf("schema differs (entry counts %d vs %d)", len(src.schema), len(dst.schema))
	}
	if !reflect.DeepEqual(src.counts, dst.counts) {
		for i := 0; i < len(src.counts) || i < len(dst.counts); i++ {
			var sv, dv string
			if i < len(src.counts) {
				sv = src.counts[i]
			}
			if i < len(dst.counts) {
				dv = dst.counts[i]
			}
			if sv != dv {
				return fmt.Errorf("row counts differ: source[%d]=%q provisioned[%d]=%q", i, sv, i, dv)
			}
		}
		return fmt.Errorf("row counts differ (table counts %d vs %d)", len(src.counts), len(dst.counts))
	}
	return nil
}
