// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

// purge_scope_test.go — QS-6 owner-audit regression tests for the
// re-scoped PurgeFixtures.  The owner found two gaps in the previous
// implementation:
//
//  1. observations were deleted by provenance='fixture' alone, without
//     restricting the fixture source id;
//  2. the orphan-service (and detached-asset) sweep had no fixture
//     scoping at all, so an orphan service of a REAL source could be
//     deleted by a fixture purge.
//
// The tests below pin the new contract, covering every scenario the
// owner asked for: mixed fixture/non-fixture observations, multiple data
// sources, orphan non-fixture services, shared assets with both fixture
// and non-fixture relations, idempotency AND transactional rollback
// (with real SQLite ABORT triggers, so the rollback path itself is
// exercised, not just success paths), and explicit before/after counts.

import (
	"context"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// purgeCounts is the explicit before/after verification the owner
// asked for — read directly from the tables, not from PurgeStats.
type purgeCounts struct {
	obs        int64
	obsFixture int64
	services   int64
	assets     int64
}

func readPurgeCounts(t *testing.T, s *Store) purgeCounts {
	t.Helper()
	var c purgeCounts
	must := func(q string, dst *int64) {
		t.Helper()
		if err := s.DB.QueryRow(q).Scan(dst); err != nil {
			t.Fatalf("count %q: %v", q, err)
		}
	}
	must(`SELECT count(*) FROM observations`, &c.obs)
	must(`SELECT count(*) FROM observations WHERE provenance = 'fixture'`, &c.obsFixture)
	must(`SELECT count(*) FROM services`, &c.services)
	must(`SELECT count(*) FROM assets`, &c.assets)
	return c
}

// TestPurgeScopesToFixtureSourceOnly — mixed fixture/non-fixture
// observations across MULTIPLE data sources: only the fixture source's
// rows disappear; every other source's rows survive untouched; the
// shared asset survives (non-fixture relation), the fixture-only asset
// goes.
func TestPurgeScopesToFixtureSourceOnly(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	fixtureSrc := ensureSource(t, s, "fixture")
	realA := ensureSource(t, s, "real-a")
	realB := ensureSource(t, s, "real-b")

	// Shared asset: fixture AND two real sources observe it.
	sharedFix := assetFact(fixtureSrc, storage.AssetKindIP, "198.51.100.80")
	sharedRealA := assetFact(realA, storage.AssetKindIP, "198.51.100.80")
	sharedRealA.Observation.Provenance = "scan-http"
	sharedRealB := assetFact(realB, storage.AssetKindIP, "198.51.100.80")
	sharedRealB.Observation.Provenance = "scan-http"
	// Fixture-only asset (must be purged).
	fixOnly := assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.80")
	// Real-only asset (must never be touched).
	realOnly := assetFact(realA, storage.AssetKindIP, "198.51.100.81")
	realOnly.Observation.Provenance = "scan-http"
	if _, err := s.IngestFacts(ctx, []storage.Fact{sharedFix, sharedRealA, sharedRealB, fixOnly, realOnly}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	before := readPurgeCounts(t, s)
	if before.obsFixture != 2 || before.obs != 5 || before.assets != 3 {
		t.Fatalf("setup counts = %+v (want 2 fixture obs, 5 obs, 3 assets)", before)
	}

	st, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if st.ObservationsRemoved != 2 || st.ServicesRemoved != 0 || st.AssetsRemoved != 1 {
		t.Fatalf("purge stats = %+v (want 2 obs, 0 services, 1 asset)", st)
	}

	after := readPurgeCounts(t, s)
	if after.obsFixture != 0 {
		t.Errorf("fixture observations must be gone: %+v", after)
	}
	if after.obs != before.obs-2 {
		t.Errorf("exactly the 2 fixture observations must be removed: %+v → %+v", before, after)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM observations WHERE source_id = ?`, realA).Scan(&n)
	if n != 2 {
		t.Errorf("real-a must keep both its observations (mixed data + multi-source protection), got %d", n)
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM observations WHERE source_id = ?`, realB).Scan(&n)
	if n != 1 {
		t.Errorf("real-b must keep its observation, got %d", n)
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '198.51.100.80'`).Scan(&n)
	if n != 1 {
		t.Errorf("the shared asset must survive (non-fixture relation)")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '198.51.100.81'`).Scan(&n)
	if n != 1 {
		t.Errorf("the real-only asset must survive")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '203.0.113.80'`).Scan(&n)
	if n != 0 {
		t.Errorf("the fixture-only asset must be purged")
	}
}

// TestPurgeSparesOrphanNonFixtureService — an orphan service of a REAL
// source (its observation was removed by something else) must NEVER be
// deleted by a fixture purge; the fixture service with the same orphan
// fate IS deleted.
func TestPurgeSparesOrphanNonFixtureService(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	fixtureSrc := ensureSource(t, s, "fixture")
	realA := ensureSource(t, s, "real-a")

	// Real service that will become orphaned (retention-style removal).
	if _, err := s.IngestFacts(ctx, []storage.Fact{serviceFact(realA, "198.51.100.82", 8443, "https", "nginx")}); err != nil {
		t.Fatalf("ingest real: %v", err)
	}
	if _, err := s.DB.Exec(`DELETE FROM observations WHERE source_id = ?`, realA); err != nil {
		t.Fatalf("drop real observation: %v", err)
	}
	// Fixture service (will be purged with its observation).
	if _, err := s.IngestFacts(ctx, []storage.Fact{serviceFact(fixtureSrc, "203.0.113.82", 443, "http", "fixture-svc")}); err != nil {
		t.Fatalf("ingest fixture: %v", err)
	}

	before := readPurgeCounts(t, s)
	if before.services != 2 {
		t.Fatalf("setup: want 2 services (1 orphan real, 1 fixture), got %+v", before)
	}

	st, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if st.ServicesRemoved != 1 {
		t.Fatalf("exactly the fixture service must go, stats = %+v", st)
	}
	after := readPurgeCounts(t, s)
	if after.services != before.services-1 {
		t.Errorf("exactly one service must be removed: %+v → %+v", before, after)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM services s JOIN assets a ON a.id = s.asset_id
	                    WHERE a.value = '198.51.100.82' AND s.port = 8443`).Scan(&n)
	if n != 1 {
		t.Errorf("the ORPHAN NON-FIXTURE service must survive the fixture purge (owner gap #2)")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM services s JOIN assets a ON a.id = s.asset_id
	                    WHERE a.value = '203.0.113.82' AND s.port = 443`).Scan(&n)
	if n != 0 {
		t.Errorf("the fixture service must be purged")
	}
}

// TestPurgeSharedAssetKeepsNonFixtureRelations — an asset observed by
// BOTH the fixture source (through service F) and a real source
// (through service R): the purge removes F and its observation but
// keeps R, its observation, and the asset itself.
func TestPurgeSharedAssetKeepsNonFixtureRelations(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	fixtureSrc := ensureSource(t, s, "fixture")
	realA := ensureSource(t, s, "real-a")

	fixSvc := serviceFact(fixtureSrc, "198.51.100.83", 443, "http", "fixture-web")
	realSvc := serviceFact(realA, "198.51.100.83", 8443, "https", "real-web")
	realSvc.Observation.Provenance = "scan-http"
	if _, err := s.IngestFacts(ctx, []storage.Fact{fixSvc, realSvc}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	before := readPurgeCounts(t, s)
	if before.services != 2 || before.obsFixture != 1 {
		t.Fatalf("setup: want 2 services / 1 fixture obs (service-level fact), got %+v", before)
	}

	st, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if st.ObservationsRemoved != 1 || st.ServicesRemoved != 1 || st.AssetsRemoved != 0 {
		t.Fatalf("purge stats = %+v (want 1 obs, 1 service, 0 assets)", st)
	}
	after := readPurgeCounts(t, s)
	if after.assets != before.assets {
		t.Errorf("the SHARED asset must survive (still has a real service): %+v → %+v", before, after)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM services s JOIN assets a ON a.id = s.asset_id
	                    WHERE a.value = '198.51.100.83' AND s.port = 8443 AND s.product = 'real-web'`).Scan(&n)
	if n != 1 {
		t.Errorf("the real service must survive with its relation to the shared asset")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM services s JOIN assets a ON a.id = s.asset_id
	                    WHERE a.value = '198.51.100.83' AND s.port = 443 AND s.product = 'fixture-web'`).Scan(&n)
	if n != 0 {
		t.Errorf("the fixture service must be purged")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM observations o JOIN services sv ON sv.id = o.service_id
	                    WHERE sv.product = 'real-web'`).Scan(&n)
	if n != 1 {
		t.Errorf("the real observation must survive")
	}
}

// TestPurgeIdempotentAndRollback — running the purge twice is safe (the
// second run removes nothing), and a mid-transaction failure rolls the
// WHOLE purge back (no partial deletion).  The rollback is exercised
// twice with real SQLite RAISE(ABORT) triggers: once on the
// observations delete (early failure) and once on the services delete
// (the observation delete has already run inside the transaction — a
// partial-commit bug would show up as missing fixture observations).
func TestPurgeIdempotentAndRollback(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	fixtureSrc := ensureSource(t, s, "fixture")
	realA := ensureSource(t, s, "real-a")

	sharedFix := assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.90")
	sharedReal := assetFact(realA, storage.AssetKindIP, "203.0.113.90")
	sharedReal.Observation.Provenance = "scan-http"
	fixSvc := serviceFact(fixtureSrc, "203.0.113.91", 443, "http", "fixture-web")
	if _, err := s.IngestFacts(ctx, []storage.Fact{sharedFix, sharedReal, fixSvc}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	before := readPurgeCounts(t, s)
	if before.obsFixture != 2 || before.services != 1 || before.assets != 2 {
		t.Fatalf("setup counts = %+v (want 2 fixture obs, 1 service, 2 assets)", before)
	}

	// Idempotency: first purge removes the fixture rows, the second run
	// is a no-op with identical table counts.
	st1, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge 1: %v", err)
	}
	if st1.ObservationsRemoved != 2 || st1.ServicesRemoved != 1 || st1.AssetsRemoved != 1 {
		t.Fatalf("purge 1 stats = %+v (want 2 fixture obs, 1 fixture service, 1 asset — the shared asset keeps its real observation)", st1)
	}
	after1 := readPurgeCounts(t, s)
	st2, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge 2: %v", err)
	}
	if st2 != (PurgeStats{}) {
		t.Fatalf("second purge must be a no-op, got %+v", st2)
	}
	after2 := readPurgeCounts(t, s)
	if after1 != after2 {
		t.Fatalf("idempotency broken: counts changed on the second run %+v → %+v", after1, after2)
	}

	// Rollback path (mid-transaction): rebuild fixture data, then fail
	// the SERVICES delete — the observation delete already ran, so any
	// partial-commit bug would leave the fixture observations gone.
	rebuild := []storage.Fact{
		assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.92"),
		serviceFact(fixtureSrc, "203.0.113.92", 443, "http", "fixture-web"),
	}
	if _, err := s.IngestFacts(ctx, rebuild); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	failed := readPurgeCounts(t, s)

	mustAbort := func(t *testing.T, on, name string) {
		t.Helper()
		if _, err := s.DB.Exec(`CREATE TRIGGER ` + name + ` BEFORE DELETE ON ` + on + `
			BEGIN SELECT RAISE(ABORT, 'purge-rollback-drill'); END`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		_, err := s.PurgeFixtures(ctx)
		if err == nil {
			t.Fatalf("the purge must fail while %s deletion is aborted", on)
		}
		if _, derr := s.DB.Exec(`DROP TRIGGER ` + name); derr != nil {
			t.Fatalf("drop trigger: %v", derr)
		}
	}

	// (a) early failure: the observations delete aborts.
	mustAbort(t, "observations", "t_purge_boom_obs")
	if now := readPurgeCounts(t, s); now != failed {
		t.Errorf("rollback (observations) must restore every row: %+v → %+v", failed, now)
	}
	// (b) mid failure: the services delete aborts after the observation
	//     delete ran inside the same transaction.
	mustAbort(t, "services", "t_purge_boom_svc")
	if now := readPurgeCounts(t, s); now != failed {
		t.Errorf("rollback (services) must restore the already-deleted observations too: %+v → %+v", failed, now)
	}

	// After both drills the purge still works normally.
	if _, err := s.PurgeFixtures(ctx); err != nil {
		t.Fatalf("purge after drills: %v", err)
	}
	if now := readPurgeCounts(t, s); now.obsFixture != 0 {
		t.Errorf("fixture data must be gone after the post-drill purge: %+v", now)
	}
	// The surviving real data was never touched during any drill.
	if now := readPurgeCounts(t, s); now.assets < 1 {
		t.Errorf("the real asset must survive every drill: %+v", now)
	}
}

// TestPurgeRemovesCorpusTaggedFixtureAssets — corpus assets carry
// Sources=['fixture'] (the fixture source tag), which is a fixture
// trace, not a non-fixture relation: once fully detached they are
// purged like the rest of the dataset (the CLI contract says "delete
// every fixture-tagged … asset").  An asset tagged with the fixture
// source AND a real source survives — the real tag is a live relation.
func TestPurgeRemovesCorpusTaggedFixtureAssets(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	fixtureSrc := ensureSource(t, s, "fixture")
	realA := ensureSource(t, s, "real-a")

	fixCorpus := assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.93")
	fixCorpus.Asset.Sources = []string{storage.FixtureSourceName}
	fixOnly := assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.94")
	sharedTag := assetFact(fixtureSrc, storage.AssetKindIP, "203.0.113.95")
	sharedTag.Asset.Sources = []string{storage.FixtureSourceName, "real-a"}
	if _, err := s.IngestFacts(ctx, []storage.Fact{fixCorpus, fixOnly, sharedTag}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// Keep a live observation on the shared-tag asset from the real source.
	realObs := assetFact(realA, storage.AssetKindIP, "203.0.113.95")
	realObs.Observation.Provenance = "scan-http"
	if _, err := s.IngestFacts(ctx, []storage.Fact{realObs}); err != nil {
		t.Fatalf("ingest real: %v", err)
	}

	st, err := s.PurgeFixtures(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if st.AssetsRemoved != 2 || st.ObservationsRemoved != 3 {
		t.Fatalf("purge stats = %+v (want 2 assets, 3 fixture obs)", st)
	}
	var n int
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '203.0.113.93'`).Scan(&n)
	if n != 0 {
		t.Errorf("the corpus-tagged fixture asset must be purged")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '203.0.113.94'`).Scan(&n)
	if n != 0 {
		t.Errorf("the untagged fixture asset must be purged")
	}
	_ = s.DB.QueryRow(`SELECT count(*) FROM assets WHERE value = '203.0.113.95'`).Scan(&n)
	if n != 1 {
		t.Errorf("the asset with a live real-source tag must survive (non-fixture relation)")
	}
	var srcs string
	_ = s.DB.QueryRow(`SELECT sources FROM assets WHERE value = '203.0.113.95'`).Scan(&srcs)
	if containsStr(srcs, storage.FixtureSourceName) {
		t.Errorf("the fixture tag must be stripped from the surviving asset's sources: %s", srcs)
	}
}
