// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package observe is GSEER's v0.3.2 ACTIVE observation regime — the
// P2/PAC counterpart of internal/collect (passive).  Two separate
// observers live here:
//
//	HTTPObserver — one explicit HTTP GET against a scoped target;
//	              records service-level facts with HTTP evidence.
//	TLSObserver  — one explicit TLS handshake against a scoped target;
//	              records service-level facts with certificate evidence.
//
// # The authorization contract (v0.3.2 master prompt §8)
//
// NOTHING in this package touches the network without passing the
// default-deny Gateway first.  A missing, invalid, expired, revoked,
// protocol-mismatched, port-mismatched or over-budget scope is DENY,
// the denial is audited (scan_audits), and no probe fires.  Private
// networks (loopback, RFC 1918, ULA, link-local, CGNAT, multicast,
// unspecified) are reachable ONLY when the operator's scope explicitly
// covers the exact address or range — an operator-scoped loopback
// target is the supported way to observe a service you run yourself.
//
// # DNS rebinding protection
//
// The gateway resolves the hostname ONCE, validates EVERY returned
// address against the scope registry (and the private-network rule),
// and hands the observer a Decision that pins the validated address.
// Observers dial THAT address — never re-resolving the hostname — so a
// rebind between authorization and connection cannot redirect the probe.
// Redirects re-enter the gateway hop by hop.
//
// # Honest recording
//
// An observer records exactly what the target answered, with the
// observation timestamp and the acting scope in evidence.  A connection
// failure is recorded as a FAILED OBSERVATION in the run result — it is
// never evidence that an asset does not exist.  Provenance is the
// observer's own label ("scan-http" / "scan-tls"), never "fixture",
// never a passive connector's label.
//
// # Search ≠ Scan (ADR-0010, unchanged)
//
// internal/search, searchlite, api and dashboard still import nothing
// from this package.  Observation is always an explicit `gseer scan`
// command; nothing here runs uninvoked and there is no scheduler.
package observe
