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

package observe

// lease_renewal_test.go — FINAL-security-microfix FIX B part 2: the
// renewal heartbeat.  Proven here at the observer level:
//
//   - a run that outlives its lease TTL keeps its slot via renewal
//     (cross-process: a second store handle cannot take the slot
//     mid-run, and the row is gone after the run);
//   - a renewal failure is fatal for the observation: no NEW
//     connection is opened (HTTP loop gate + dial gate, TLS pre-dial
//     gate), in-flight work completes honestly;
//   - the heartbeat goroutine never outlives the run (Stop is
//     idempotent and waits).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func TestRunOutlivingTTLPersistsThroughRenewal(t *testing.T) {
	// The response takes longer than the lease TTL; the renewal
	// heartbeat (TTL/4) must keep the slot held for the WHOLE run —
	// proven by a second, independent store handle (what another
	// process would see) being refused mid-run — and release it after.
	dbPath := filepath.Join(t.TempDir(), "renewal-e2e.db")
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := sqlite.Migrate(context.Background(), db.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := sqlite.NewStore(db.DB)
	t.Cleanup(func() { _ = store.Close() })
	peer, err := sqlite.Open(dbPath) // the "second process"
	if err != nil {
		t.Fatalf("open peer: %v", err)
	}
	if _, err := sqlite.Migrate(context.Background(), peer.DB); err != nil {
		t.Fatalf("migrate peer: %v", err)
	}
	peerStore := sqlite.NewStore(peer.DB)
	t.Cleanup(func() { _ = peerStore.Close() })

	sc := &storage.Scope{
		Kind: storage.ScopeKindIP, Value: "127.0.0.1", Mode: "allow",
		Protocols: []string{"http"}, Ports: nil, // ports filled below
		MaxConcurrency: 1, MaxRequests: 2,
	}
	gw := &Gateway{
		Store:              store,
		LeaseTTL:           150 * time.Millisecond, // deliberately shorter than the response
		LeaseRenewInterval: 40 * time.Millisecond,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mid-response (≈ 3 TTLs in), the lease must still be held: the
		// second process is refused.
		time.Sleep(250 * time.Millisecond)
		if _, aerr := peerStore.AcquireScanLease(context.Background(), sc.ID, 1, 0, "second-process"); aerr == nil {
			t.Errorf("RENEWAL BROKE: the second process took the slot while the observation was still running")
			return
		}
		fmt.Fprint(w, "<html><title>Slow Target</title>ok</html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	sc.Ports = []int{port}
	if _, err := store.CreateScope(context.Background(), sc); err != nil {
		t.Fatalf("create scope: %v", err)
	}

	obs := &HTTPObserver{GW: gw}
	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil || !res.OK {
		t.Fatalf("the run must survive its own TTL via renewal: err=%v res=%+v", err, res)
	}
	var n int
	if serr := store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM scan_leases`).Scan(&n); serr != nil {
		t.Fatalf("count leases: %v", serr)
	}
	if n != 0 {
		t.Fatalf("the finished run must hold no lease rows (found %d)", n)
	}
}

func TestRenewalFailureBlocksNewConnectionsHTTP(t *testing.T) {
	// Hop 1 completes; the heartbeat fails while it is in flight; the
	// redirect hop (a NEW connection) must be refused — recorded, not
	// sent.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
		time.Sleep(120 * time.Millisecond) // the renewal tick fails mid-hop
		fmt.Fprint(w, "redirecting")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	sc := scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 51; sc.MaxRequests = 3 })
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	fs.renewErr = errors.New("lease storage down")
	g := &Gateway{Store: fs, LeaseRenewInterval: 20 * time.Millisecond}
	obs := &HTTPObserver{GW: g}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatalf("a renewal failure is an observation OF FAILURE, not a run error: %v", err)
	}
	if res.OK || !strings.Contains(res.Failure, "concurrency lease lost") {
		t.Fatalf("the hop after the renewal failure must be refused: %+v", res)
	}
	if hits != 1 {
		t.Fatalf("no NEW connection after the renewal failure (hits=%d)", hits)
	}
}

func TestRenewalFailureBlocksTLSConnection(t *testing.T) {
	var accepts int
	raw, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	go func() {
		for {
			c, err := raw.Accept()
			if err != nil {
				return
			}
			accepts++
			_ = c.Close()
		}
	}()
	port := raw.Addr().(*net.TCPAddr).Port
	defer func() { _ = raw.Close() }()

	sc := scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"tls"}, []int{port},
		func(sc *storage.Scope) { sc.ID = 52 })
	fs := &fakeStore{scopes: []storage.Scope{sc}}
	fs.renewErr = errors.New("lease storage down")
	// Deterministic window: the pre-dial re-validation's audit sleeps,
	// the heartbeat tick fails inside that window, the LAST gate (after
	// re-validation, before the socket) refuses the connection.
	fs.auditDelay = 80 * time.Millisecond
	g := &Gateway{Store: fs, LeaseRenewInterval: 15 * time.Millisecond}
	obs := &TLSObserver{GW: g, Timeout: 3 * time.Second}

	res, err := obs.Run(context.Background(), "127.0.0.1", port)
	if err == nil || !strings.Contains(err.Error(), "concurrency lease lost") {
		t.Fatalf("the TLS connection after a renewal failure must be refused: %v %+v", err, res)
	}
	if accepts != 0 {
		t.Fatalf("no TLS connection may be opened after the renewal failure (accepts=%d)", accepts)
	}
}

func TestLeaseGuardStopsWithoutGoroutineLeak(t *testing.T) {
	fs := &fakeStore{scopes: []storage.Scope{scopeAt(storage.ScopeKindIP, "127.0.0.1", []string{"http"}, []int{8080},
		func(sc *storage.Scope) { sc.ID = 53 })}}
	g := &Gateway{Store: fs, LeaseRenewInterval: 5 * time.Millisecond}

	before := runtime.NumGoroutine()
	l, err := g.AcquireLease(context.Background(),
		&Decision{Allowed: true, Scope: &fs.scopes[0], Limits: Limits{MaxConcurrency: 1, MaxRequests: 1, MaxTotalBytes: 0}})
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	guard := g.StartLeaseRenewal(context.Background(), l)
	time.Sleep(30 * time.Millisecond)
	if renewals := fs.renewCalls.Load(); renewals < 2 {
		t.Fatalf("the heartbeat must renew on its cadence (got %d renewals)", renewals)
	}
	guard.Stop()
	guard.Stop() // idempotent — must not panic or deadlock
	select {
	case <-guard.done:
	default:
		t.Fatalf("Stop must wait for the heartbeat goroutine to finish")
	}
	time.Sleep(20 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("renewal goroutine leaked: before=%d after=%d", before, after)
	}
	// A guard stopped at rest never latches Lost.
	if guard.Lost() {
		t.Fatalf("a healthy stopped guard must not report Lost")
	}
}
