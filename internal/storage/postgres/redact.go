// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package postgres

import (
	"net/url"
)

// redact.go — credential redaction for diagnostics (M3 discipline).
//
// The raw DSN (postgres://user:password@host:port/db?sslmode=...) is
// NEVER logged or printed anywhere in GSEER (M2 logging restriction;
// preflight §5.7; owner decision D-M3-10).  Every diagnostic surface —
// doctor output, DB_MIGRATION_LOCK_TIMEOUT, E_DB_UNREACHABLE,
// E_DB_MIGRATION_DIRTY, setup's "migrations applied" report — is built
// from RedactDSN output only.
//
// SEC-6 (the structured slog attribute-replacement handler) lands in
// M10; until then, redaction is enforced BY CONSTRUCTION: no code path
// formats the raw DSN.  The raw DSN is held only in the in-memory
// config.DatabaseConfig and passed directly to pgx.Connect /
// pgxpool.New / the migrate driver — never to a formatter or logger.

// RedactDSN strips the userinfo (user, password) from a URL-shaped
// PostgreSQL DSN and returns the display-safe form:
//
//	postgres://host:port/dbname?sslmode=...
//
// The M2 fmtDSN builds DSNs via net/url, so operator-provided
// database.dsn values are expected to be URL-shaped too (documented in
// .env.example and docs/INSTALL.md).  A non-URL DSN returns an error —
// callers then fall back to omitting the DSN from output entirely
// (never a partial or best-effort redaction).
func RedactDSN(rawDSN string) (string, error) {
	u, err := url.Parse(rawDSN)
	if err != nil {
		return "", err
	}
	u.User = nil
	return u.String(), nil
}

// MustRedactDSN is the panic-free convenience wrapper for rendering
// paths where a malformed DSN means the diagnostic omits the DSN
// segment rather than failing the whole command.  It returns the
// redacted form, or "" when the DSN cannot be parsed.
func MustRedactDSN(rawDSN string) string {
	s, err := RedactDSN(rawDSN)
	if err != nil {
		return ""
	}
	return s
}
