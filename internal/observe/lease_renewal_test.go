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
	// heartbeat (explicit 80ms cadence) must keep the slot held for the
	// WHOLE run —
	// proven by a second, independent store handle (what another
	// process would see) being refused mid-run — and release it after.
	// The margins (TTL 300ms, renewal 80ms, mid-run check at 500ms)
	// are sized for slow CI schedulers: windows-latest can stall a
	// goroutine for ~100ms under load, so the staleness bound (the
	// renewal interval) must stay well below the TTL, and the mid-run
	// check must land comfortably after several renewal rounds.
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
		LeaseTTL:           300 * time.Millisecond, // deliberately shorter than the response
		LeaseRenewInterval: 80 * time.Millisecond,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mid-response (≈ 1.7 TTLs in — the 500ms sleep against the
		// 300ms TTL), the lease must still be held: the second process
		// is refused.
		time.Sleep(500 * time.Millisecond)
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
	// re-validation, before the socket) refuses the connection.  The
	// window (150ms) is sized for slow CI schedulers — the first failing
	// tick must land well inside it even when the runner stalls.
	fs.auditDelay = 150 * time.Millisecond
	g := &Gateway{Store: fs, LeaseRenewInterval: 20 * time.Millisecond}
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

	// The leak this test guards against is SPECIFIC: the heartbeat
	// goroutine surviving Stop.  The check is therefore a targeted
	// stack-marker count, NOT a raw runtime.NumGoroutine() delta —
	// process-wide goroutine counts also include unrelated runtime and
	// transport goroutines that appear and disappear around slow CI
	// schedulers (observed on windows-latest), so a raw delta cannot
	// distinguish a leaked heartbeat from background noise and fails
	// spuriously on exactly the slowest platforms.
	const heartbeatMarker = "observe.(*LeaseGuard).loop"
	before := countStacksMatching(heartbeatMarker)

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
	// The heartbeat goroutine must be GONE, not merely signalled: the
	// OS may schedule the final return slightly after close(done), so
	// poll with a bounded settle window before failing (and dump the
	// stacks on failure — actionable evidence).
	deadline := time.Now().Add(2 * time.Second)
	for {
		now := countStacksMatching(heartbeatMarker)
		if now <= before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("renewal goroutine leaked: %d matching stacks of %q before, %d after\nstacks:\n%s",
				before, heartbeatMarker, now, allGoroutineStacks())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A guard stopped at rest never latches Lost.
	if guard.Lost() {
		t.Fatalf("a healthy stopped guard must not report Lost")
	}
}

// allGoroutineStacks dumps every live goroutine's stack (failure
// evidence for the leak assertion).
func allGoroutineStacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// countStacksMatching counts live goroutines whose stack mentions the
// given function marker.
func countStacksMatching(marker string) int {
	return strings.Count(allGoroutineStacks(), marker)
}
