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

// observe_e2e_test.go — the observers' end-to-end behavior against
// REAL local HTTP/TLS servers (httptest — the operator-owned loopback
// targets the product supports), persisted through the REAL personal
// SQLite engine and verified down to the stored observations.  No
// external network: everything listens on 127.0.0.1 and the scopes
// explicitly authorize exactly that.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// jsonUnmarshal / timeParseUTC are the test-side decoders for the
// stored evidence rows.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func timeParseUTC(s string) time.Time {
	t, _ := time.Parse("2006-01-02T15:04:05.000000Z", s)
	if t.IsZero() {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

// e2eFixture: a real personal SQLite store + a gateway over it.
type e2eFixture struct {
	t  *testing.T
	gw *Gateway
	db *sqlite.Store
}

func newE2E(t *testing.T) *e2eFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "observe-e2e.db")
	db, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := sqlite.Migrate(context.Background(), db.DB); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	store := sqlite.NewStore(db.DB)
	t.Cleanup(func() { _ = store.Close() })
	return &e2eFixture{t: t, gw: &Gateway{Store: store}, db: store}
}

// addScope registers one loopback scope for the given port(s).
func (f *e2eFixture) addScope(protocols []string, ports []int, mut func(*storage.Scope)) *storage.Scope {
	f.t.Helper()
	sc := &storage.Scope{
		Kind:           storage.ScopeKindCIDR,
		Value:          "127.0.0.1/32",
		Mode:           "allow",
		Note:           "operator-owned loopback test target",
		Protocols:      protocols,
		Ports:          ports,
		MaxConcurrency: 1,
		MaxRequests:    6,
	}
	if mut != nil {
		mut(sc)
	}
	if _, err := f.db.CreateScope(context.Background(), sc); err != nil {
		f.t.Fatalf("create scope: %v", err)
	}
	return sc
}

func TestHTTPObserverEndToEnd(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "gseer-e2e/1.0")
		fmt.Fprint(w, "<html><head><title>GSEER E2E Target</title></head><body>ok</body></html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("HTTP observation failed: %v", err)
	}
	if !res.OK {
		t.Fatalf("observation reported failure: %s", res.Failure)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	if res.Title != "GSEER E2E Target" {
		t.Fatalf("title = %q", res.Title)
	}
	if res.Server != "gseer-e2e/1.0" {
		t.Fatalf("server header = %q", res.Server)
	}
	if res.Facts < 1 || res.Ingested < 1 {
		t.Fatalf("no facts ingested: %+v", res)
	}
	if res.Provenance != ProvenanceHTTP {
		t.Fatalf("provenance = %s", res.Provenance)
	}

	// The service row + observation + evidence are REALLY in the index.
	svc, obs_row := f.queryServiceObservation(t, "127.0.0.1", port)
	if svc == nil {
		t.Fatalf("no service row persisted for 127.0.0.1:%d", port)
	}
	if svc.Protocol != "http" || svc.Transport != "tcp" {
		t.Fatalf("service shape: %+v", svc)
	}
	if obs_row == nil {
		t.Fatalf("no observation persisted")
	}
	if obs_row.Provenance != ProvenanceHTTP {
		t.Fatalf("observation provenance = %s", obs_row.Provenance)
	}
	if ev, ok := obs_row.Evidence["http"].(map[string]any); !ok {
		t.Fatalf("evidence missing the http object: %+v", obs_row.Evidence)
	} else {
		if ev["title"] != "GSEER E2E Target" || ev["server"] != "gseer-e2e/1.0" {
			t.Fatalf("evidence http fields: %+v", ev)
		}
	}
	if ev, ok := obs_row.Evidence["scan"].(map[string]any); !ok || ev["result"] != "observed" {
		t.Fatalf("evidence scan object: %+v", obs_row.Evidence)
	}
}

func TestHTTPObserverFollowsAuthorizedRedirect(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	// One server, two ports are impossible on one httptest listener —
	// use ONE server that redirects to a path on itself (relative hop),
	// so a single port suffices.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "<html><title>After Hop</title></html>")
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("redirect run failed: %v", err)
	}
	if res.Status != http.StatusOK || res.Title != "After Hop" {
		t.Fatalf("redirect chain did not land on the final hop: %+v", res)
	}
	if len(res.Redirects) < 2 {
		t.Fatalf("redirect hops not recorded: %v", res.Redirects)
	}
}

func TestHTTPObserverRecordsHTTPSRedirectNotFollowed(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	// R36 contract: an absolute https:// Location IS followed — the
	// observer speaks https over the same authorized socket — but the
	// NEW host still re-enters the gateway per hop; an out-of-scope
	// https target is DENIED and the chain records the denial honestly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://other.example/start")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f.addScope([]string{"http"}, []int{port}, nil)

	obs := &HTTPObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	joined := strings.Join(res.Redirects, " | ")
	if strings.Contains(joined, "RECORDED-NOT-FOLLOWED") {
		t.Fatalf("https redirect must be attempted (R36 port-aware scheme), not recorded-not-followed: %v", res.Redirects)
	}
	if !strings.Contains(joined, "DENIED") {
		t.Fatalf("out-of-scope https hop must be denied by the gateway: %v", res.Redirects)
	}
}

func TestHTTPObserverBudgetAndDenials(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	port := srvPort(t, srv)

	// max_requests = 1: the initial request runs, the redirect hop is
	// refused by the BUDGET (recorded honestly), not by the network.
	f.addScope([]string{"http"}, []int{port}, func(sc *storage.Scope) { sc.MaxRequests = 1 })
	obs := &HTTPObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("budget run failed: %v", err)
	}
	if res.OK {
		t.Fatalf("budget exhaustion must surface as a recorded failure: %+v", res)
	}
	if !strings.Contains(res.Failure, "budget") {
		t.Fatalf("failure text: %s", res.Failure)
	}
	if hits != 1 {
		t.Fatalf("server hit %d times, want exactly the budgeted 1", hits)
	}

	// The budget scope permits only `port`; scanning port+1 (unscoped
	// port, same address) → deny, exit-path error, NO probe.
	obs2 := &HTTPObserver{GW: f.gw}
	_, derr := obs2.Run(ctx, "127.0.0.1", port+1)
	if derr == nil || !strings.Contains(derr.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("unscoped port must be denied: %v", derr)
	}
	if hits != 1 {
		t.Fatalf("a denied scan must not touch the network (hits=%d)", hits)
	}

	// The denial trail is in scan_audits.
	audits, aerr := f.db.ListScanAudits(ctx, 50)
	if aerr != nil {
		t.Fatalf("list audits: %v", aerr)
	}
	foundDeny := false
	for _, a := range audits {
		if a.Decision == "deny" && a.Reason == ReasonPortNotPermitted {
			foundDeny = true
		}
	}
	if !foundDeny {
		t.Fatalf("port denial not audited: %+v", audits)
	}
}

func TestHTTPObserverConnectionFailureIsRecordedNotAbsence(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	// Port 1 on loopback: nothing listens; the scope explicitly
	// authorizes the address+port (the operator owns the loopback).
	f.addScope([]string{"http"}, []int{1}, nil)
	obs := &HTTPObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("the RUN must succeed (the observation failed, not the run): %v", err)
	}
	if res.OK {
		t.Fatalf("nothing listens on port 1 — must be a recorded failure")
	}

	// The failed observation is IN the index, marked as a failure.
	_, obsRow := f.queryServiceObservation(t, "127.0.0.1", 1)
	if obsRow == nil {
		t.Fatalf("failed observation must still be recorded")
	}
	scan := obsRow.Evidence["scan"].(map[string]any)
	if scan["result"] != "failed" {
		t.Fatalf("evidence must mark the failure: %+v", scan)
	}
}

func TestTLSObserverEndToEnd(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls target")
	}))
	defer srv.Close()
	port := srvPort(t, srv)
	f.addScope([]string{"tls"}, []int{port}, nil)

	obs := &TLSObserver{GW: f.gw}
	res, err := obs.Run(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("TLS observation failed: %v", err)
	}
	if !res.OK {
		t.Fatalf("TLS handshake failed: %s", res.Failure)
	}
	if res.TLSVersion == "" || res.CipherSuite == "" {
		t.Fatalf("handshake state not captured: %+v", res)
	}
	if len(res.SANDNSNames) == 0 {
		t.Fatalf("httptest server cert carries SAN DNS names; got none (res: %+v)", res)
	}
	if res.Provenance != ProvenanceTLS {
		t.Fatalf("provenance = %s", res.Provenance)
	}

	// Evidence keys feed latest_tls: version + subject CN + issuer CN
	// are really stored, and the service row speaks https.
	svc, obsRow := f.queryServiceObservation(t, "127.0.0.1", port)
	if svc == nil || svc.Protocol != "https" {
		t.Fatalf("service row: %+v", svc)
	}
	tlsEv, ok := obsRow.Evidence["tls"].(map[string]any)
	if !ok {
		t.Fatalf("evidence missing tls object: %+v", obsRow.Evidence)
	}
	if tlsEv["version"] != res.TLSVersion || tlsEv["cert_subject_cn"] != res.SubjectCN {
		t.Fatalf("tls evidence mismatch: %+v", tlsEv)
	}
}

func TestTLSObserverDeniedWithoutScope(t *testing.T) {
	f := newE2E(t)
	ctx := context.Background()
	obs := &TLSObserver{GW: f.gw}
	_, err := obs.Run(ctx, "127.0.0.1", 8443)
	if err == nil || !strings.Contains(err.Error(), "E_SCOPE_DENIED") {
		t.Fatalf("unscoped TLS target must be denied: %v", err)
	}
}

// srvPort extracts the ephemeral port of a test server.
func srvPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	addr := srv.Listener.Addr().String()
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		t.Fatalf("unparseable test server address %q", addr)
	}
	var p int
	if _, err := fmt.Sscanf(addr[idx+1:], "%d", &p); err != nil {
		t.Fatalf("unparseable port in %q: %v", addr, err)
	}
	return p
}

// queryServiceObservation reads back the service row and the newest
// observation for (ip, port) through the personal engine.
func (f *e2eFixture) queryServiceObservation(t *testing.T, ip string, port int) (*storage.Service, *storage.Observation) {
	t.Helper()
	ctx := context.Background()
	var svc *storage.Service
	row := f.db.DB.QueryRowContext(ctx, `SELECT id, asset_id, port, transport, protocol FROM services WHERE port = ? ORDER BY id DESC LIMIT 1`, port)
	var id, assetID, p int
	var transport, protocol string
	err := row.Scan(&id, &assetID, &p, &transport, &protocol)
	if err == nil {
		svc = &storage.Service{ID: int64(id), AssetID: int64(assetID), Port: p, Transport: transport, Protocol: protocol}
	}
	var obs *storage.Observation
	orow := f.db.DB.QueryRowContext(ctx, `SELECT o.source_id, o.observed_at, o.payload_hash, o.source_cursor, o.provenance, o.evidence
        FROM observations o JOIN services s ON s.id = o.service_id
        WHERE s.port = ? ORDER BY o.id DESC LIMIT 1`, port)
	var (
		sourceID    int64
		observedAt  string
		payloadHash string
		cursor      string
		provenance  string
		evidenceRaw string
	)
	if err := orow.Scan(&sourceID, &observedAt, &payloadHash, &cursor, &provenance, &evidenceRaw); err == nil {
		ev := map[string]any{}
		_ = jsonUnmarshal([]byte(evidenceRaw), &ev)
		obs = &storage.Observation{
			SourceID:     sourceID,
			ObservedAt:   timeParseUTC(observedAt),
			PayloadHash:  payloadHash,
			SourceCursor: cursor,
			Provenance:   provenance,
			Evidence:     ev,
		}
	}
	return svc, obs
}
