// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

// funcs.go — the gseer_* scalar functions registered into the SQLite
// engine.  Three exist, and every query in the personal dialect may
// reference them (the planner emits them; the suppression backstop
// trigger calls two of them):
//
//   gseer_ip_in_cidr(addr_text, cidr_text) → 1|0|NULL
//       netip containment for IN_CIDR and the CIDR backstop rule;
//       NULL (never matched) for NULL/invalid inputs, mirroring how a
//       PG comparison against an unparseable value errors rather than
//       silently matching.
//   gseer_ts(value) → canonical "2006-01-02T15:04:05.000000Z" | NULL
//       normalizes any RFC 3339 / date-only text to the fixed-width
//       UTC microsecond form so evidence-sourced cert_expiry compares
//       chronologically.
//   gseer_now_micro() → the current canonical UTC microsecond string
//       (the backstop trigger's expiry clock).
//
// Registration is process-global (modernc driver semantics) and happens
// in init() so every connection — including ones opened before a query
// references the functions — resolves them.

import (
	"database/sql/driver"
	"fmt"
	"net/netip"
	"time"

	"modernc.org/sqlite"
)

func init() {
	// IN_CIDR: containment with netip (IPv4 and IPv6, canonical text in).
	sqlite.MustRegisterDeterministicScalarFunction("gseer_ip_in_cidr", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		a, ok1 := asString(args[0])
		c, ok2 := asString(args[1])
		if !ok1 || !ok2 {
			return nil, nil // NULL in → NULL out → no match
		}
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("gseer_ip_in_cidr: %q is not a CIDR prefix", c)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("gseer_ip_in_cidr: %q is not an IP address", a)
		}
		if prefix.Masked().Contains(addr.Unmap()) {
			return int64(1), nil
		}
		return int64(0), nil
	})

	// gseer_ts: normalize RFC 3339 / date-only text to fixed-width UTC.
	sqlite.MustRegisterDeterministicScalarFunction("gseer_ts", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		s, ok := asString(args[0])
		if !ok {
			return nil, nil
		}
		t, err := ParseTS(s)
		if err != nil {
			return nil, nil // unparsable → NULL → never matches
		}
		return FormatTS(t), nil
	})

	// gseer_now_micro: the trigger/planner wall clock (non-deterministic
	// by nature; registered as a plain scalar function).
	sqlite.MustRegisterScalarFunction("gseer_now_micro", 0, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		return FormatTS(time.Now().UTC()), nil
	})
}

func asString(v driver.Value) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case []byte:
		return string(t), true
	default:
		return "", false
	}
}
