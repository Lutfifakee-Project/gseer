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

package relations

// relations_test.go — R76/R77 regression: relations are derived ONLY from
// stored evidence; kinds are correct; provenance (observed_at/source)
// rides on every edge; shared-certificate traversal works; absent
// evidence yields NO invented edges.

import (
	"context"
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func relTestStore(t *testing.T) *sqlite.Store {
	t.Helper()
	res, err := sqlite.Open(t.TempDir() + "/gseer.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return sqlite.NewStore(res.DB)
}

func bookID(cursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("rel:" + cursor))
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}

// ingestFact writes one fact with the given asset, optional service and
// evidence payload (same Fact path as every collector).
func ingestFact(t *testing.T, st *sqlite.Store, srcID int64, cursor string, at time.Time,
	kind storage.AssetKind, value string, ip, domain, hostname *string,
	port int, evidence map[string]any) {
	t.Helper()
	a := storage.Asset{Kind: kind, Value: value, IP: ip, Domain: domain, Hostname: hostname, Sources: []string{"fixture"}}
	f := storage.Fact{
		Asset: a,
		Observation: storage.Observation{
			ID: bookID(cursor), SourceID: srcID, SourceCursor: cursor,
			PayloadHash: "hash-" + cursor, ObservedAt: at,
			Provenance: "fixture", Evidence: evidence,
		},
	}
	if port > 0 {
		f.Service = &storage.Service{Port: port, Transport: "tcp", Protocol: "https"}
	}
	if _, err := st.IngestFact(context.Background(), &f); err != nil {
		t.Fatalf("ingest %s: %v", cursor, err)
	}
}

func kindsSeen(rels []Relation) map[string]int {
	m := map[string]int{}
	for _, r := range rels {
		m[r.Kind]++
	}
	return m
}

func TestExploreServiceTLSTechEdges(t *testing.T) {
	st := relTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.50"
	ipP := &ip
	ingestFact(t, st, src, "t1", base, storage.AssetKindIP, ip, ipP, nil, nil, 443, map[string]any{
		"http":        map[string]any{"status": 200, "title": "Home", "server": "nginx"},
		"tls":         map[string]any{"version": "TLSv1.3", "cert_subject_cn": "shop.example", "cert_serial": "SER123", "cert_sans_dns": "shop.example,api.example"},
		"fingerprint": map[string]any{"technologies": []any{"nginx", "WordPress"}},
	})
	rels, err := Explore(ctx, st.DB, ip, "", 10)
	if err != nil {
		t.Fatalf("explore: %v", err)
	}
	seen := kindsSeen(rels)
	for _, want := range []string{KindService, KindTLSCert, KindTLSShared, KindTech} {
		if seen[want] == 0 {
			t.Errorf("missing %s edge; got %v", want, seen)
		}
	}
	// SAN traversal must surface api.example from cert_sans_dns (R77:
	// hostnames connected to a certificate).
	foundAPI := false
	for _, r := range rels {
		if r.Kind == KindTLSShared && r.To == "api.example" {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Errorf("cert_tls_shared did not surface SAN api.example")
	}
	// Every edge carries a source and observed_at (R77 provenance).
	for _, r := range rels {
		if r.ObservedAt == "" || r.Source == "" {
			t.Errorf("%s edge missing provenance: %+v", r.Kind, r)
		}
	}
}

func TestExploreDNSEdgesAndNoInvention(t *testing.T) {
	st := relTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	host := "app.example"
	hostP := &host
	// hostname with A record evidence
	ingestFact(t, st, src, "d1", base, storage.AssetKindHostname, host, nil, nil, hostP, 0,
		map[string]any{"dns": map[string]any{"query": host, "a": []any{"203.0.113.77"}}})
	rels, err := Explore(ctx, st.DB, host, KindDNSResolves, 10)
	if err != nil {
		t.Fatalf("explore: %v", err)
	}
	if len(rels) != 1 || rels[0].To != "203.0.113.77" || rels[0].Detail != "A" {
		t.Fatalf("dns_resolves_to edge wrong: %+v", rels)
	}
	// Ingest the bare ip asset (as the DNS collector would).  It HAS real
	// evidence: app.example's DNS record names it → exactly one dns_reverse
	// edge (R77: domains connected to an IP), with provenance.
	ipAddr := "203.0.113.77"
	ingestFact(t, st, src, "d2", base, storage.AssetKindIP, ipAddr, &ipAddr, nil, nil, 0, nil)
	rels2, err := Explore(ctx, st.DB, "203.0.113.77", "", 10)
	if err != nil {
		t.Fatalf("explore 2: %v", err)
	}
	if len(rels2) != 1 || rels2[0].Kind != KindDNSReverse || rels2[0].To != host {
		t.Fatalf("expected exactly one dns_reverse edge to %s, got %+v", host, rels2)
	}
	// A second IP with NO evidence anywhere produces NO edges (no invention).
	ipAddr2 := "203.0.113.99"
	ingestFact(t, st, src, "d3", base, storage.AssetKindIP, ipAddr2, &ipAddr2, nil, nil, 0, nil)
	rels3, err := Explore(ctx, st.DB, ipAddr2, "", 10)
	if err != nil {
		t.Fatalf("explore 3: %v", err)
	}
	if len(rels3) != 0 {
		t.Fatalf("asset without evidence must have zero edges, got %+v", rels3)
	}
	// Unknown asset = clean error, not fabricated output.
	if _, err := Explore(ctx, st.DB, "nope.invalid", "", 10); err == nil {
		t.Fatalf("unknown asset must error")
	}
}

func TestExploreSharedCTCertificate(t *testing.T) {
	st := relTestStore(t)
	ctx := context.Background()
	src, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	base := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	sha := "aabbccdd00112233"
	for _, dom := range []string{"a.example", "b.example"} {
		d := dom
		ingestFact(t, st, src, "ct-"+dom, base, storage.AssetKindDomain, dom, nil, &d, nil, 0,
			map[string]any{"ctlog": map[string]any{"subject_cn": dom, "leaf_sha256": sha, "issuer": "Test CA"}})
	}
	rels, err := Explore(ctx, st.DB, "a.example", KindCTShared, 10)
	if err != nil {
		t.Fatalf("explore: %v", err)
	}
	if len(rels) != 1 || rels[0].To != "b.example" {
		t.Fatalf("cert_ct_shared edge wrong: %+v", rels)
	}
	if rels[0].ObservedAt == "" || rels[0].Source == "" {
		t.Fatalf("shared-cert edge missing provenance: %+v", rels[0])
	}
}

// TestKindsDocumented pins the kind vocabulary (R77 contract surface).
func TestKindsDocumented(t *testing.T) {
	if len(Kinds()) != 11 {
		t.Fatalf("kind vocabulary changed: %v", Kinds())
	}
	seen := map[string]bool{}
	for _, k := range Kinds() {
		if seen[k] {
			t.Fatalf("duplicate kind %q", k)
		}
		seen[k] = true
	}
}

var _ = fmt.Sprintf
