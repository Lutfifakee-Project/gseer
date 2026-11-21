// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// release_layout_test.go — pins the PRODUCTION channel contract: the
// default manifest URL must match the GitHub Release layout the pipeline
// publishes (tag `central-dataset`, stable asset names), and the CLI's
// URL resolution must fetch the payload from exactly that layout.  The
// loopback server here is a TEST FIXTURE serving the same PATH SHAPE the
// real release page serves (plain http is only allowed on loopback; the
// production URL is https).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/config"
)

// releaseTag and releaseAssetNames are the workflow's publication
// contract (.github/workflows/dataset.yml): the rolling tag and the two
// stable asset names.
const (
	releaseTag = "central-dataset"
	// ghReleaseAssetPath mirrors the GitHub release download layout:
	// /releases/download/<tag>/<asset>.
	ghReleaseAssetPath = "/releases/download/" + releaseTag + "/"
)

func TestOfficialChannelMatchesGitHubReleaseLayout(t *testing.T) {
	official := config.OfficialDatasetManifestURL
	// 1. The default channel URL must be the manifest asset of the
	// `central-dataset` release in the GitHub download layout.
	if !strings.HasPrefix(official, "https://github.com/") {
		t.Errorf("official channel must be https on github.com: %s", official)
	}
	wantSuffix := "/releases/download/" + releaseTag + "/" + ManifestFilename
	if !strings.HasSuffix(official, wantSuffix) {
		t.Errorf("official channel %s must end with %s", official, wantSuffix)
	}
	// 2. Resolving the payload from the official URL must produce the
	// release layout path of the OTHER stable asset.
	payloadURL, err := ResolveArtifactURL(official, PayloadFilename)
	if err != nil {
		t.Fatalf("resolve payload from the official URL: %v", err)
	}
	if !strings.HasSuffix(payloadURL, "/releases/download/"+releaseTag+"/"+PayloadFilename) {
		t.Errorf("resolved payload URL %s is not in the release layout", payloadURL)
	}
	// 3. The asset names must match the workflow's upload contract.
	if ManifestFilename != "gseer-dataset-manifest.json" || PayloadFilename != "gseer-dataset.ndjson.gz" {
		t.Errorf("asset names drifted from the workflow contract: %s / %s", ManifestFilename, PayloadFilename)
	}
}

// TestReleaseLayoutChannelServesTheJourney serves a loopback channel with
// the GitHub release PATH SHAPE, then runs manifest fetch → payload fetch
// (resolved by ResolveArtifactURL) → import → row checks.  This proves
// the production layout is consumable by exactly the CLI code path.
func TestReleaseLayoutChannelServesTheJourney(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	recs := []Record{
		domainRec("central-dns", now, "example.com"),
		serviceRec("central-scan", now.Add(-time.Second), "93.184.216.34", 443),
	}
	dir := t.TempDir()
	m := writeTestDataset(t, dir, 5, recs)
	manifestBody, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	payloadBody, err := os.ReadFile(path.Join(dir, PayloadFilename))
	if err != nil {
		t.Fatal(err)
	}

	// TEST FIXTURE: loopback server with the GitHub release path shape.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path.Clean(r.URL.Path) {
		case ghReleaseAssetPath + ManifestFilename:
			_, _ = w.Write(manifestBody)
		case ghReleaseAssetPath + PayloadFilename:
			_, _ = w.Write(payloadBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	channel := srv.URL + ghReleaseAssetPath + ManifestFilename

	// The journey: manifest → payload (resolved from the release layout)
	// → atomic import.
	f := NewFetcher()
	parsed, err := f.FetchManifest(context.Background(), channel)
	if err != nil {
		t.Fatalf("manifest fetch from the release layout: %v", err)
	}
	if parsed.DatasetVersion != 5 {
		t.Fatalf("dataset version = %d, want 5", parsed.DatasetVersion)
	}
	payloadPath, err := f.FetchPayload(context.Background(), channel, parsed)
	if err != nil {
		t.Fatalf("payload fetch (resolved) from the release layout: %v", err)
	}
	defer func() { _ = os.Remove(payloadPath) }()

	dbPath := newTestDB(t)
	res, err := Import(context.Background(), ImportOptions{
		DBPath:      dbPath,
		PayloadPath: payloadPath,
		Manifest:    parsed,
		ManifestURL: channel,
	})
	if err != nil {
		t.Fatalf("import from the release-layout channel: %v", err)
	}
	if res.Stats.ObservationsInserted != 2 {
		t.Fatalf("observations inserted = %d, want 2", res.Stats.ObservationsInserted)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var services int
	if err := db.QueryRow(`SELECT COUNT(*) FROM services WHERE port = 443`).Scan(&services); err != nil {
		t.Fatal(err)
	}
	if services != 1 {
		t.Fatalf("services with port 443 = %d, want 1", services)
	}
}
