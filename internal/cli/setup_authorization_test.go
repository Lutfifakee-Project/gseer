// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// setup_authorization_test.go — R4 P0-3 regression battery: DEFAULT
// SETUP performs NO active TLS observation and never infers an
// authorization from a PTR record or the egress IP.  The egress context
// is INFORMATIONAL ONLY.  Requirements 3 (explicit authorized
// observation works) and 4 (unauthorized targets are rejected) are
// pinned by scan_scope_test.go (E_SCOPE_DENIED, exit 5, unscoped-port
// denial) and referenced from the audit matrix.
//
// Determinism: the egress-echo and PTR-resolution seams
// (egressEchoHTTP / egressLookupAddr) are injected — no test touches
// the network.

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// ptrContextSeams pins the happy context: a public egress IP whose PTR
// resolves to a host under example.net (so the OLD code WOULD have
// created a scope and observed TLS — these tests prove it no longer
// does).
func ptrContextSeams(t *testing.T) {
	t.Helper()
	oldEcho, oldLookup := egressEchoHTTP, egressLookupAddr
	egressEchoHTTP = func(ctx context.Context, url string) (int, string, error) {
		return http.StatusOK, "203.0.113.7", nil
	}
	egressLookupAddr = func(ip string) ([]string, error) {
		return []string{"host.example.net."}, nil
	}
	t.Cleanup(func() { egressEchoHTTP, egressLookupAddr = oldEcho, oldLookup })
}

// scopeCountRows counts every row in the scopes table of the personal
// database the bootstrap just provisioned (the default path under the
// isolated HOME).
func scopeCountRows(t *testing.T) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", defaultPersonalDBPath())
	if err != nil {
		t.Fatalf("open personal db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var n int64
	if err := db.QueryRow("SELECT COUNT(*) FROM scopes").Scan(&n); err != nil {
		t.Fatalf("count scopes: %v", err)
	}
	return n
}

// setupBootstrapOffline drives the full default setup (passive
// bootstrap; dataset stage skipped via --offline) in an isolated HOME.
func setupBootstrapOffline(t *testing.T) string {
	t.Helper()
	old := flags.configPath
	t.Cleanup(func() { flags.configPath = old })
	flags.configPath = ""
	cmd := &cobra.Command{Use: "setup"}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	if err := runSetupBootstrapDefault(cmd, "", true); err != nil {
		t.Fatalf("offline bootstrap setup: %v\n%s", err, out.String())
	}
	return out.String()
}

// TestDefaultSetupPerformsNoActiveTLSObservation proves requirement 1:
// with a fully resolvable egress context (PTR → domain), the default
// setup registers the passive bootstrap sources and performs ZERO
// active TLS observation — no scan-tls provenance in the output and no
// observation stage.
func TestDefaultSetupPerformsNoActiveTLSObservation(t *testing.T) {
	withDatasetEnv(t)
	ptrContextSeams(t)
	out := setupBootstrapOffline(t)

	if !strings.Contains(out, "passive discovery complete — NO active observation was performed") {
		t.Errorf("setup output must state the no-active-observation contract:\n%s", out)
	}
	if strings.Contains(out, "provenance=scan-tls") {
		t.Errorf("setup must never run TLS observation (scan-tls provenance found):\n%s", out)
	}
	if strings.Contains(out, "[ ok  ] observation: ") {
		t.Errorf("the observation stage must be gone from default setup:\n%s", out)
	}
}

// TestNoPTRDomainAutoAuthorized proves requirement 2: even with a
// derived registrable domain, NO scope row exists after default setup —
// nothing is inferred into an authorization.
func TestNoPTRDomainAutoAuthorized(t *testing.T) {
	withDatasetEnv(t)
	ptrContextSeams(t)
	out := setupBootstrapOffline(t)

	if n := scopeCountRows(t); n != 0 {
		t.Errorf("default setup created %d scope row(s) — PTR-derived domains must never be auto-authorized:\n%s", n, out)
	}
	if !strings.Contains(out, "host.example.net") {
		t.Errorf("the context stage should have derived the PTR domain (precondition):\n%s", out)
	}
	if !strings.Contains(out, "gseer scope add domain_suffix") {
		t.Errorf("setup must point at the EXPLICIT authorization path:\n%s", out)
	}
}
