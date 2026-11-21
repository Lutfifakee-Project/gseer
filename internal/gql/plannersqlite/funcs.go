// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package plannersqlite

import (
	"net/netip"
)

// funcs.go — compile-time helpers shared by the SQL emission paths.
//
// The runtime counterparts of these helpers are registered as SQLite
// scalar functions by internal/storage/sqlite (gseer_ip_in_cidr,
// gseer_ts, gseer_now_micro); this file holds the pure-Go validation
// the planner needs to fail a bad IN_CIDR value at COMPILE time — the
// PG dialect fails at execution with a SQLSTATE, and personal mode
// must not silently turn a typo into an empty result.

// parsePrefix parses and masks a CIDR prefix ("198.51.100.0/24").
// A bare IP is NOT accepted: the operator writes the network explicitly.
func parsePrefix(s string) (netip.Prefix, netip.Addr, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, err
	}
	m := p.Masked()
	return m, m.Addr(), nil
}
