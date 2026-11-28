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

package relations

// dialect.go — one query surface, two storage dialects (PG parity, R94).
// The relations engine runs unchanged on SQLite (personal mode) and
// PostgreSQL (self-hosted mode): the wrapper rewrites ?-placeholders to
// $n for PostgreSQL, casts JSONB columns to text, and normalizes
// timestamps (SQLite TEXT RFC-3339 vs PostgreSQL TIMESTAMPTZ) into the
// same RFC-3339 UTC string so provenance output is identical on both.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Dialect selects the storage engine behind the *sql.DB handle.
type Dialect int

const (
	DialectSQLite   Dialect = iota // personal mode (mattn/modernc SQLite)
	DialectPostgres                // self-hosted mode (pgx/v5 stdlib)
)

// dbx is the dialect-aware query wrapper used by every relation probe.
type dbx struct {
	db  *sql.DB
	dia Dialect
}

// query rewrites the SQL for the dialect and runs it.
func (x *dbx) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return x.db.QueryContext(ctx, x.sql(query), args...)
}

// queryRow is the single-row form of query.
func (x *dbx) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return x.db.QueryRowContext(ctx, x.sql(query), args...)
}

// sql rewrites ?-placeholders to PostgreSQL $n (in order, no ? appears
// inside string literals in this package's queries) and casts the JSONB
// dns_record column to text on PostgreSQL.
func (x *dbx) sql(query string) string {
	if x.dia != DialectPostgres {
		return query
	}
	query = strings.ReplaceAll(query, "t.dns_record", "t.dns_record::text")
	n := 0
	var b strings.Builder
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString(fmt.Sprintf("$%d", n))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// asStr normalizes a scanned value into the string form the Relation
// struct carries: SQLite returns TEXT directly; PostgreSQL returns
// TIMESTAMPTZ as time.Time (formatted RFC-3339 UTC) and JSONB as []byte.
func asStr(v any) string {
	switch tv := v.(type) {
	case nil:
		return ""
	case string:
		return tv
	case []byte:
		return string(tv)
	case time.Time:
		return tv.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("%v", tv)
	}
}

// scanStrs scans a row of string-typed columns through asStr.
func scanStrs(rows *sql.Rows, dest []*string) error {
	tmp := make([]any, len(dest))
	for i := range dest {
		var v any
		tmp[i] = &v
	}
	if err := rows.Scan(tmp...); err != nil {
		return err
	}
	for i := range dest {
		*dest[i] = asStr(*tmp[i].(*any))
	}
	return nil
}

// scanRow reads one row into dialect-neutral values (asStr-normalized).
func scanRow(row *sql.Row, n int) ([]any, error) {
	vals := make([]any, n)
	ptrs := make([]any, n)
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := row.Scan(ptrs...); err != nil {
		return nil, err
	}
	return vals, nil
}
