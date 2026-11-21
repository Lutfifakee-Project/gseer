// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package observe

// budget_test.go — FIX C (v0.3.2 security microfix): max_total_bytes is
// an ACCUMULATED budget for the entire observation run.  The metric is
// precisely "bytes read from HTTP response bodies" (headers excluded),
// counted across EVERY redirect hop, never reset on a redirect; the
// single one-byte truncation probe is counted because it is read.  A
// read error is surfaced honestly (never reported as a complete
// response); exhaustion past the final response is recorded as
// truncation; exhaustion before a further hop is recorded-not-sent.
// Lease release (FIX D) is verified here too: a finished run holds no
// scan_leases row.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveBytes emits an EXACTLY n-byte body (plain padding — the size,
// not the markup, is what these tests assert).
func serveBytes(n int) string {
	return strings.Repeat("x", n)
}

func TestHTTPBudgetSingleResponseBelowExactAbove(t *testing.T) {
	cases := []struct {
		name      string
		body      int
		budget    int64
		wantOK    bool
		wantTrunc bool
		wantBytes int64
	}{
		{"below budget", 100, 1000, true, false, 100},
		{"exactly at budget", 1000, 1000, true, false, 1000},
		{"above budget", 2000, 1000, true, true, 1001}, // 1000 + the 1-byte probe
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2E(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, serveBytes(tc.body))
			}))
			defer srv.Close()
			port := srvPort(t, srv)
			f.addScope([]string{"http"}, []int{port}, nil)

			obs := &HTTPObserver{GW: f.gw, MaxBytesOverride: tc.budget}
			res, err := obs.Run(context.Background(), "127.0.0.1", port)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if res.OK != tc.wantOK {
				t.Fatalf("ok = %v, want %v (failure: %s)", res.OK, tc.wantOK, res.Failure)
			}
			if res.Truncated != tc.wantTrunc {
				t.Fatalf("truncated = %v, want %v", res.Truncated, tc.wantTrunc)
			}
			if res.BytesRead != tc.wantBytes {
				t.Fatalf("bytes_read = %d, want %d (the accumulated-body-bytes metric)", res.BytesRead, tc.wantBytes)
			}
		})
	}
}

func TestHTTPBudgetAccumulatesAcrossRedirects(t *testing.T) {
	// 500 + 500 against a 1200 budget: BOTH hops fully read — the old
	// per-hop bug would have allowed 2×1200; the accumulated budget
	// reads exactly 1000.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, serveBytes(500))
			return
		}
		fmt.Fprint(w, serveBytes(500))
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f := newE2E(t)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw, MaxBytesOverride: 1200}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.OK || res.Truncated || res.Status != http.StatusOK {
		t.Fatalf("combined 1000 < budget 1200 must complete: %+v", res)
	}
	if res.BytesRead != 1000 {
		t.Fatalf("bytes must ACCUMULATE across hops: got %d, want 1000", res.BytesRead)
	}
	if hits != 2 {
		t.Fatalf("two hops expected, got %d", hits)
	}

	// Exact accumulation: 600 + 600 against a 1200 budget.
	var hits2 int
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits2++
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, serveBytes(600))
			return
		}
		fmt.Fprint(w, serveBytes(600))
	}))
	defer srv2.Close()
	port2 := srvPort(t, srv2)
	f2 := newE2E(t)
	f2.addScope([]string{"http"}, []int{port2}, nil)

	obs2 := &HTTPObserver{GW: f2.gw, MaxBytesOverride: 1200}
	res2, err := obs2.Run(context.Background(), "127.0.0.1", port2)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res2.OK || res2.Truncated || res2.BytesRead != 1200 {
		t.Fatalf("combined exactly-at-budget must complete untruncated: %+v", res2)
	}
}

func TestHTTPBudgetExhaustedAcrossRedirectsRecorded(t *testing.T) {
	// 600 + 600 + another redirect against a 1000 budget: hop 2 reads
	// its remaining 401 bytes (400 + probe → truncated), hop 3 is
	// RECORDED, NOT SENT — the exhaustion is never a silent complete
	// response.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "/next"+fmt.Sprint(hits))
		w.WriteHeader(http.StatusFound)
		fmt.Fprint(w, serveBytes(600))
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f := newE2E(t)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw, MaxBytesOverride: 1000}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.OK {
		t.Fatalf("budget exhaustion must NOT report a complete response: %+v", res)
	}
	if !strings.Contains(res.Failure, "response-byte budget exhausted") {
		t.Fatalf("failure must name the exhausted budget: %s", res.Failure)
	}
	if hits != 2 {
		t.Fatalf("the exhausted hop must be recorded-not-sent (hits=%d, want 2)", hits)
	}
	if res.BytesRead != 1001 { // 600 + 400 + probe
		t.Fatalf("accumulated bytes = %d, want 1001", res.BytesRead)
	}

	// The stored evidence carries the accumulated counter (persisted
	// facts stay accurate).
	_, obsRow := f.queryServiceObservation(t, "127.0.0.1", port)
	if obsRow == nil {
		t.Fatalf("observation must be persisted")
	}
	scan := obsRow.Evidence["scan"].(map[string]any)
	if got, _ := scan["response_bytes"].(float64); int64(got) != 1001 {
		t.Fatalf("evidence response_bytes = %v, want 1001", scan["response_bytes"])
	}
	if got, _ := scan["byte_budget"].(float64); int64(got) != 1000 {
		t.Fatalf("evidence byte_budget = %v, want 1000", scan["byte_budget"])
	}
}

func TestHTTPBodyReadErrorIsRecordedNotComplete(t *testing.T) {
	// A mid-body connection failure must be a RECORDED failure — the
	// pre-fix readCapped silently swallowed it into "no body, all fine".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5000")
		fmt.Fprint(w, serveBytes(64))
		w.(http.Flusher).Flush()
		panic("connection dies mid-body")
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f := newE2E(t)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw, MaxBytesOverride: 100000}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("a body read error is an observation of failure, not a run error: %v", err)
	}
	if res.OK {
		t.Fatalf("a broken body must NOT report a complete response: %+v", res)
	}
	if !strings.Contains(res.Failure, "read error") {
		t.Fatalf("failure must name the body read error: %s", res.Failure)
	}
}

func TestHTTPEmptyResponseIsHonest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	port := srvPort(t, srv)
	f := newE2E(t)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw, MaxBytesOverride: 1000}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.OK || res.Truncated || res.BytesRead != 0 || res.Title != "" {
		t.Fatalf("empty response: %+v", res)
	}
}

func TestScanRunReleasesConcurrencyLease(t *testing.T) {
	// FIX D lifecycle: a finished run holds NO scan_leases row — the
	// next run (and the next process) can take the slot again.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	port := srvPort(t, srv)
	f := newE2E(t)
	f.addScope([]string{"http"}, []int{port}, nil) // MaxConcurrency defaults to 1

	obs := &HTTPObserver{GW: f.gw}
	for i := 0; i < 2; i++ {
		res, err := obs.Run(context.Background(), "127.0.0.1", port)
		if err != nil || !res.OK {
			t.Fatalf("run %d must succeed under the 1-slot lease: %v %+v", i+1, err, res)
		}
		var n int
		if serr := f.db.DB.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM scan_leases`).Scan(&n); serr != nil {
			t.Fatalf("count leases: %v", serr)
		}
		if n != 0 {
			t.Fatalf("run %d left %d lease row(s) behind", i+1, n)
		}
	}
}
