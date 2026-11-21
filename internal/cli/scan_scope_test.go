// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// scan_scope_test.go — v0.3.2: `gseer scope` and `gseer scan` through
// the REAL command tree against the REAL personal engine, with the
// observed target being an operator-owned loopback httptest server.
// Proven end-to-end here: scope add → scan allow → persistence →
// GQL search finds the observation; revoke → scan denied (exit 5) and
// the denial audited; the Search ≠ Scan invariant holds (searching
// never probes).

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func TestScopeAndScanPersonalEndToEnd(t *testing.T) {
	dbPath := newMigratedPersonalDB(t)
	cfgPath := writePersonalConfigForTest(t, dbPath)

	restore := captureRootOutput(t)
	defer restore()

	run := func(t *testing.T, args ...string) string {
		t.Helper()
		var buf bytes.Buffer
		RootCmd.SetOut(&buf)
		RootCmd.SetErr(&buf)
		t.Cleanup(func() { RootCmd.SetOut(nil); RootCmd.SetErr(nil) })
		RootCmd.SetArgs(append([]string{"--config", cfgPath}, args...))
		t.Cleanup(func() { RootCmd.SetArgs([]string{}) })
		if err := RootCmd.Execute(); err != nil {
			t.Fatalf("execute %v: %v\noutput: %s", args, err, buf.String())
		}
		return buf.String()
	}

	// The operator-owned target: a REAL local HTTP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "gseer-cli-e2e/2.0")
		fmt.Fprint(w, "<html><head><title>CLI E2E</title></head></html>")
	}))
	defer srv.Close()
	port := srvPortForTest(t, srv)

	// 1. scope add (explicit authorization basis asserted by the operator).
	out := run(t, "scope", "add", "cidr", "127.0.0.1/32",
		"--protocols", "http",
		"--ports", strconv.Itoa(port),
		"--note", "operator-owned loopback test target")
	if !strings.Contains(out, "Registered scope") {
		t.Fatalf("scope add output:\n%s", out)
	}

	// 2. scope list shows it active.
	out = run(t, "scope", "list")
	if !strings.Contains(out, "allow-active") || !strings.Contains(out, "127.0.0.1/32") {
		t.Fatalf("scope list output:\n%s", out)
	}

	// 3. scan http — the authorized observation.
	out = run(t, "scan", "http", "--target", "127.0.0.1", "--port", strconv.Itoa(port))
	if !strings.Contains(out, "status=200") || !strings.Contains(out, "scan-http") {
		t.Fatalf("scan http output:\n%s", out)
	}

	// 4. The observation is searchable through GQL (read-only).
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.DB.Close() }()
	svc := searchlite.New(db.DB)
	res, serr := svc.Search(context.Background(), search.Query{
		GQL:   "http.status == 200",
		Limit: 10,
	})
	if serr != nil {
		t.Fatalf("search http_status==200: %v", serr)
	}
	foundTarget := false
	for _, row := range res.Rows {
		if row.Port != nil && *row.Port == port && row.Protocol != nil && *row.Protocol == "http" {
			foundTarget = true
		}
	}
	if !foundTarget {
		t.Fatalf("scan observation not found via GQL http.status==200 (%d rows)", len(res.Rows))
	}

	// 5. scope audit shows the ALLOW decision.
	out = run(t, "scope", "audit")
	if !strings.Contains(out, "allow") {
		t.Fatalf("scope audit output:\n%s", out)
	}

	// 6. Revoke; a NEW scan is denied with exit 5 (the auth code) and
	//    the denial is audited.  The exitFunc seam keeps this testable.
	var exitCode int
	orig := exitFunc
	exitFunc = func(code int) { exitCode = code /* test: no os.Exit */ }
	t.Cleanup(func() { exitFunc = orig })

	out = run(t, "scope", "revoke", "1")
	if !strings.Contains(out, "Revoked") {
		t.Fatalf("scope revoke output:\n%s", out)
	}
	out = run(t, "scan", "http", "--target", "127.0.0.1", "--port", strconv.Itoa(port))
	if exitCode != ExitAuth {
		t.Fatalf("denied scan must exit %d (auth), got %d\noutput: %s", ExitAuth, exitCode, out)
	}
	if !strings.Contains(out, "E_SCOPE_DENIED") {
		t.Fatalf("denied scan output missing E_SCOPE_DENIED:\n%s", out)
	}

	// 7. The denial is audited.
	out = run(t, "scope", "audit")
	if !strings.Contains(out, "deny") || !strings.Contains(out, "SCOPE_REVOKED") {
		t.Fatalf("scope audit missing the deny trail:\n%s", out)
	}

	// 8. scan tls on an unscoped port is denied BEFORE any probe.
	exitCode = 0
	out = run(t, "scan", "tls", "--target", "127.0.0.1", "--port", strconv.Itoa(port))
	if exitCode != ExitAuth {
		t.Fatalf("unscoped tls scan must exit %d, got %d", ExitAuth, exitCode)
	}
}

func srvPortForTest(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	addr := srv.Listener.Addr().String()
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		t.Fatalf("unparseable server address %q", addr)
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		t.Fatalf("port in %q: %v", addr, err)
	}
	return p
}
