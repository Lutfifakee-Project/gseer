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

package searchlite_test

// cert_projection_test.go — v0.3.2 field-breadth acceptance (approved
// STAGE 4 item 6): cert.sn / cert.domain (migration 0005 projection)
// and the IP-aggregation compat aliases (ip_country/ip_region/ip_city/
// ip_after/ip_before) are searchable over the REAL personal engine —
// data in through the storage layer, GQL out.

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func certProjectionFixture(t *testing.T) *searchlite.Service {
	t.Helper()
	res, err := sqlite.Open(filepath.Join(t.TempDir(), "certproj.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = res.DB.Close() })
	ctx := context.Background()
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := sqlite.NewStore(res.DB)
	srcID, err := store.EnsureSource(ctx, "test-tls", "scan-tls", "test terms", nil)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ip := "203.0.113.77"
	assetID, _, err := store.UpsertAsset(ctx, &storage.Asset{
		Kind: storage.AssetKindIP, Value: ip, IP: &ip,
		GeoCountry: "ID", GeoRegion: "ID-JK", GeoCity: "Jakarta",
		Sources: []string{"scan-tls"}, FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	svcID, _, err := store.UpsertService(ctx, &storage.Service{
		AssetID: assetID, Port: 443, Transport: "tcp", Protocol: "https", Name: "https",
		FirstSeen: now, LastSeen: now,
	})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	obs := &storage.Observation{
		ID: 101, SourceID: srcID, AssetID: assetID, ServiceID: &svcID,
		ObservedAt: now, PayloadHash: "sha256:certproj", SourceCursor: "v1|batch:cert|rec:0",
		Provenance: "scan-tls",
		Evidence: map[string]any{
			"tls": map[string]any{
				"version": "TLSv1.3", "cert_subject_cn": "www.example.id",
				"cert_issuer_cn": "R3", "cert_serial": "04f2a9c1de7b",
				"cert_sans_dns": []string{"www.example.id", "example.id", "api.example.id"},
				"cert_expiry":   now.Add(720 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	if _, _, err := store.InsertObservation(ctx, obs); err != nil {
		t.Fatalf("observation: %v", err)
	}
	return searchlite.New(res.DB)
}

func TestCertSerialSearch(t *testing.T) {
	svc := certProjectionFixture(t)
	res, err := svc.Search(context.Background(), search.Query{GQL: `cert.sn = "04f2a9c1de7b"`, Limit: 10})
	if err != nil {
		t.Fatalf("cert.sn search: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("cert.sn = serial returned %d rows, want 1", len(res.Rows))
	}
	if res.Rows[0].TLSCertSerial == nil || *res.Rows[0].TLSCertSerial != "04f2a9c1de7b" {
		t.Fatalf("cert_serial not projected into the row: %+v", res.Rows[0])
	}

	// The compat wildcard match: *= patterns are user-anchored
	// (* -> %), so the substring form wraps itself in stars.
	res, err = svc.Search(context.Background(), search.Query{GQL: `cert.sn *= "*f2a9*"`, Limit: 10})
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("cert.sn contains: %v (%d rows)", err, len(res.Rows))
	}
}

func TestCertSansDomainSearch(t *testing.T) {
	svc := certProjectionFixture(t)
	ctx := context.Background()
	res, err := svc.Search(ctx, search.Query{GQL: `cert.domain CONTAINS "example.id"`, Limit: 10})
	if err != nil {
		t.Fatalf("cert.domain search: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("cert.domain CONTAINS returned %d rows, want 1", len(res.Rows))
	}
	if res.Rows[0].TLSCertSansDNS == nil ||
		*res.Rows[0].TLSCertSansDNS != "www.example.id,example.id,api.example.id" {
		t.Fatalf("SANs not projected as comma-joined text: %+v", res.Rows[0].TLSCertSansDNS)
	}
}

func TestIPAggregationAliases(t *testing.T) {
	svc := certProjectionFixture(t)
	ctx := context.Background()
	for _, gql := range []string{
		`ip_country = "ID"`,
		`ip_region = "ID-JK"`,
		`ip_city CONTAINS "Jakarta"`,
		`ip_after="2000-01-01"`,
		`ip_before="2100-01-01"`,
	} {
		res, err := svc.Search(ctx, search.Query{GQL: gql, Limit: 10})
		if err != nil {
			t.Fatalf("%s: %v", gql, err)
		}
		if len(res.Rows) != 1 {
			t.Fatalf("%s returned %d rows, want 1", gql, len(res.Rows))
		}
	}
}

// TestBareKeywordSearchPersonal — the MASTER §3 experience: an
// unquoted bare word is free text over the personal engine; a word
// that matches nothing returns zero rows (never an error).
func TestBareKeywordSearchPersonal(t *testing.T) {
	svc := certProjectionFixture(t)
	ctx := context.Background()
	res, err := svc.Search(ctx, search.Query{GQL: `example`, Limit: 10})
	if err != nil {
		t.Fatalf("bare keyword `example`: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatalf("bare keyword `example` returned 0 rows (fixture carries example.id SANs)")
	}
	res, err = svc.Search(ctx, search.Query{GQL: `lutfifakee`, Limit: 10})
	if err != nil {
		t.Fatalf("bare keyword `lutfifakee` errored: %v", err)
	}
	if len(res.Rows) != 0 {
		t.Fatalf("non-matching bare word returned rows: %d", len(res.Rows))
	}
}
