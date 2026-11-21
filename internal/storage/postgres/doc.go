// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package postgres is the PostgreSQL adapter under internal/storage.
//
// M1: package skeleton (doc.go only).  M3 lands the storage layer:
//
//   - migrations runner (golang-migrate v4, database/pgx/v5 driver,
//     source/iofs embedded migrations; one atomic transaction per
//     migration) — migrate.go, lock.go
//   - bounded advisory-lock waiting (session-level statement_timeout;
//     DB_MIGRATION_LOCK_TIMEOUT on expiry) — lock.go
//   - administrative migration commands backing `gseer db migrate
//     {status,diagnose,force}` — admin.go
//   - pgxpool lifecycle (created AFTER migrations succeed) — pool.go
//   - reachability + PG version checks (E_DB_UNREACHABLE, PD-8) —
//     reachability.go, version.go
//   - credential redaction for diagnostics (M3 discipline until SEC-6
//     lands in M10) — redact.go
//   - doctor migration-status checks (QS-4) — doctor.go
//
// M4 lands the repositories and the search_index union view.
//
// Search ≠ Scan (ADR-0010): this package contains no egress code and
// imports no collector package.  The M1 import-graph test pins that
// invariant; it must hold for every future change here.
package postgres
