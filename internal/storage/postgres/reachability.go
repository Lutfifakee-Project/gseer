// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// reachability.go — pre-migration reachability check (SPEC-05 §1:
// "setup verifies DB reachability BEFORE migrating"; owner directive §5).
//
// The check opens a single dedicated pgx connection (NOT the pool —
// the pool does not exist yet at migration time) with a bounded
// connect timeout, issues SELECT 1, and closes.  Failure produces
// E_DB_UNREACHABLE with the redacted DSN and the next command.

// reachabilityTimeout bounds the connect + ping round trip.
const reachabilityTimeout = 10 * time.Second

// CheckReachable verifies the database is reachable.  It returns nil on
// success or an E_DB_UNREACHABLE DBError.
func CheckReachable(ctx context.Context, rawDSN string) error {
	connCtx, cancel := context.WithTimeout(ctx, reachabilityTimeout)
	defer cancel()

	conn, err := pgx.Connect(connCtx, rawDSN)
	if err != nil {
		return unreachableError(err, rawDSN)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	if err := conn.Ping(connCtx); err != nil {
		return unreachableError(err, rawDSN)
	}
	return nil
}
