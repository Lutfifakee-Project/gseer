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

package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
)

// readonly.go — read-only SQLite opens for UNTRUSTED database files
// (the shared-index snapshot validation and import read a downloaded
// artifact; it must never be written to and must never be CREATED by
// the open).
//
// OpenReadOnly refuses to create or modify the file: mode=ro in the
// driver DSN makes every write fail, and a missing file is an error —
// unlike Open, which creates.  The gseer_* scalar functions are NOT
// registered on this handle: the snapshot paths never run GQL planner
// SQL, only plain SELECTs and PRAGMAs.

// OpenReadOnly opens path read-only.  The file must exist.
func OpenReadOnly(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("sqlite: cannot resolve path %q: %w", path, err)
	}
	u := url.URL{Scheme: "file", OmitHost: true, Path: filepath.ToSlash(abs)}
	dsn := u.String() + "?mode=ro"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: cannot open %q read-only: %w", abs, err)
	}
	// A missing file must fail HERE, not on the first query.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: cannot open %q read-only (missing or unreadable): %w", abs, err)
	}
	return db, nil
}
