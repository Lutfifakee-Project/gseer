// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

// dsn.go — SQ-03: safe SQLite DSN construction.
//
// The personal-mode database path is an operator-facing value: it may
// be absolute or relative and may contain spaces, Unicode, '?', '#',
// '&' or '%' characters.  The modernc driver parses a `file:` URI with
// URL-style escaping, so the path must go through url.URL's path
// escaping (NOT string concatenation) or '?' would start a query and
// '#' a fragment.  OmitHost keeps the canonical "file:/abs/path" shape
// (a "file://" authority would be misread).

import (
	"net/url"
	"path/filepath"
)

// Pragmas applied on EVERY connection the pool opens (modernc's
// `_pragma` query parameter — connection-scoped, unlike journal_mode
// which persists in the file).  These are the SQ-05 decisions:
//   - busy_timeout: a second gseer process (or any other opener of the
//     same file) waits instead of failing with SQLITE_BUSY;
//   - foreign_keys: the schema's ON DELETE CASCADE contract requires
//     it per-connection (SQLite defaults OFF);
//   - journal_mode WAL: readers never block the writer across
//     processes; the setting persists in the database file;
//   - synchronous NORMAL: WAL-safe durability with fast commits.
//
// `_txlock=immediate` is part of the same decision: every transaction
// takes the write lock AT BEGIN, so a transaction that reads-then-writes
// can never hit SQLITE_BUSY_SNAPSHOT (517) — with DEFERRED, a snapshot
// taken by a reader that another writer invalidates is NOT retried by
// busy_timeout; IMMEDIATE makes busy_timeout engage at the right point.
const pragmas = "_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"

// BuildDSN turns a filesystem path into the driver DSN.  The path is
// NOT required to exist or be absolute (relative paths stay relative —
// the CLI resolves to absolute at setup time; opening keeps whatever
// the caller passes).
func BuildDSN(path string) string {
	u := url.URL{Scheme: "file", OmitHost: true, Path: filepath.ToSlash(path)}
	dsn := u.String() // escapes spaces, '?', '#', '&' and '%' in the path
	if u.RawQuery == "" {
		return dsn + "?" + pragmas
	}
	// A path never produces a RawQuery through escaping; defensive.
	return dsn + "&" + pragmas
}
