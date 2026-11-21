// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package dataset implements the CENTRAL INTERNET-ASSET DATASET channel
// (v0.3.2 Rev 9 — owner-mandated central distribution).
//
// The project's scheduled GitHub Actions pipeline (dataset.yml) runs
// passive discovery over the terms-reviewed connectors, validates the
// evidence, and publishes a VERSIONED, CHECKSUMMED dataset artifact:
//
//	gseer-dataset-manifest.json   — version, checksum, provenance,
//	                                observed_at bounds, freshness metadata
//	gseer-dataset.ndjson.gz       — the payload: one validated fact
//	                                (asset + optional service + observation)
//	                                per NDJSON line, gzip-compressed
//
// The CLI (`gseer dataset update`, and `gseer setup` automatically)
// downloads the manifest, verifies the payload checksum AND record
// count, and imports the records into the Local Index through the SAME
// ingestion path every other writer uses — the suppression gate, the
// delivery-identity dedupe, and per-source provenance all apply.  The
// import is ATOMIC: a byte-identical pre-import snapshot (VACUUM INTO)
// is taken first; any failure (bad record, count mismatch, crash) rolls
// the database back to the snapshot; an interrupted import is recovered
// automatically on the next attempt.
//
// Search stays LOCAL — the dataset only FEEDS the index; there is no
// shared-index query service to depend on (Rev 8 architecture decision),
// and search never triggers discovery or scanning.
package dataset

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// SchemaVersion is the dataset record + manifest schema this binary
// understands.  A manifest with a HIGHER schema version is refused
// (forward-compatibility refusal — never guess).
const SchemaVersion = 1

// ManifestFilename and PayloadFilename are the stable artifact names the
// pipeline publishes (replaced per dataset version inside the rolling
// `central-dataset` release).
const (
	ManifestFilename = "gseer-dataset-manifest.json"
	PayloadFilename  = "gseer-dataset.ndjson.gz"
)

// DefaultPayloadCapBytes bounds one payload download (the updater uses
// the same order of magnitude; the dataset is a curated export, not a
// bulk feed).
const DefaultPayloadCapBytes = 512 << 20 // 512 MiB

// DefaultManifestCapBytes bounds one manifest download.
const DefaultManifestCapBytes = 4 << 20 // 4 MiB

// MaxFutureSkew bounds how far in the future an observed_at may lie and
// still validate (clock skew between pipeline and importer).
const MaxFutureSkew = 24 * time.Hour

// Manifest describes one dataset version (docs/DATASET.md).
type Manifest struct {
	// SchemaVersion must equal SchemaVersion (higher = refused).
	SchemaVersion int `json:"schema_version"`
	// DatasetVersion is the monotonic sequence (the pipeline's run
	// number).  Updates refuse older/equal versions without --force.
	DatasetVersion int64 `json:"dataset_version"`
	// GeneratedAtUTC is when the pipeline produced the artifact.
	GeneratedAtUTC time.Time `json:"generated_at_utc"`

	// Payload locates and fingerprints the NDJSON.gz payload (its URL is
	// resolved relative to the manifest URL).
	Payload PayloadInfo `json:"payload"`

	// Rows are the dataset-level row counts (validated against the
	// streamed record count at import).
	Rows RowsInfo `json:"rows"`

	// Provenance summarizes the contributing sources — one entry per
	// source name, with per-source counts and the newest observed_at.
	Provenance []ProvenanceSummary `json:"provenance"`

	// Freshness carries the observed_at window across the whole dataset.
	Freshness FreshnessInfo `json:"freshness"`

	// ValidatorVersion is the dataset-builder validation ruleset version
	// that produced the artifact (bump = stricter validation).
	ValidatorVersion string `json:"validator_version"`

	// Notes is an optional human-readable coverage statement (the
	// pipeline's honest "what this dataset covers" line).
	Notes string `json:"notes,omitempty"`
}

// PayloadInfo locates and fingerprints the payload.
type PayloadInfo struct {
	Filename  string `json:"filename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Records   int64  `json:"records"`
}

// RowsInfo counts the dataset rows by kind.
type RowsInfo struct {
	Assets       int64 `json:"assets"`
	Services     int64 `json:"services"`
	Observations int64 `json:"observations"`
}

// ProvenanceSummary is one contributing source's footprint.
type ProvenanceSummary struct {
	Source           string    `json:"source"`
	Connector        string    `json:"connector"`
	Records          int64     `json:"records"`
	NewestObservedAt time.Time `json:"newest_observed_at"`
}

// FreshnessInfo is the dataset's observed_at window (REAL evidence
// age — never the publish date alone).
type FreshnessInfo struct {
	OldestObservedAt time.Time `json:"oldest_observed_at"`
	NewestObservedAt time.Time `json:"newest_observed_at"`
}

// Record is ONE dataset payload line: a validated fact in the SAME
// shape the ingestion path consumes (asset + optional service +
// provenance-bearing observation).  Fields mirror internal/storage —
// but the record is its own schema (schema_version 1) so the artifact
// format stays stable across store-internal changes.
type Record struct {
	Schema      int               `json:"schema"`
	Asset       RecordAsset       `json:"asset"`
	Service     *RecordService    `json:"service,omitempty"`
	Observation RecordObservation `json:"observation"`
}

// RecordAsset mirrors the asset identity + typed enrichment columns.
type RecordAsset struct {
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	IP         *string  `json:"ip,omitempty"`
	Domain     *string  `json:"domain,omitempty"`
	Hostname   *string  `json:"hostname,omitempty"`
	ASN        int      `json:"asn,omitempty"`
	ASNOrg     string   `json:"asn_org,omitempty"`
	GeoCountry string   `json:"geo_country,omitempty"`
	GeoRegion  string   `json:"geo_region,omitempty"`
	GeoCity    string   `json:"geo_city,omitempty"`
	Sources    []string `json:"sources,omitempty"`
}

// RecordService is the optional service row (port evidence).
type RecordService struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Protocol  string `json:"protocol"`
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
}

// RecordObservation carries the provenance-bearing observation.  The
// per-record DB identity (id, source_cursor) is stamped by the IMPORTER
// at import time — exactly like the collect runner stamps it per
// delivery — so a re-import of the same dataset version is idempotent
// and the file never collides with a store's local ids.
type RecordObservation struct {
	// Source is the pipeline source NAME the evidence came from (the
	// importer maps it to a local data_sources row, enabled=false).
	Source     string    `json:"source"`
	Connector  string    `json:"connector"`
	ObservedAt time.Time `json:"observed_at"`
	// PayloadHash is the L2 fact-identity hash computed at collection
	// time (carried through, never recomputed at import).
	PayloadHash string `json:"payload_hash"`
	// Provenance is the provenance label (e.g. "dns", "scan-tls").
	Provenance string         `json:"provenance"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

// ParseManifest decodes + validates a manifest document.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("dataset: manifest does not parse: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// Validate enforces the manifest contract (docs/DATASET.md §3).
func (m *Manifest) Validate() error {
	if m.SchemaVersion > SchemaVersion {
		return fmt.Errorf("dataset: manifest schema_version %d is newer than this binary understands (%d) — upgrade gseer to import it",
			m.SchemaVersion, SchemaVersion)
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("dataset: manifest schema_version %d is not %d", m.SchemaVersion, SchemaVersion)
	}
	if m.DatasetVersion <= 0 {
		return fmt.Errorf("dataset: dataset_version must be a positive sequence, got %d", m.DatasetVersion)
	}
	if m.GeneratedAtUTC.IsZero() {
		return fmt.Errorf("dataset: generated_at_utc is missing")
	}
	if m.Payload.Filename != PayloadFilename {
		return fmt.Errorf("dataset: payload filename %q is not %q", m.Payload.Filename, PayloadFilename)
	}
	if !sha256HexRe.MatchString(m.Payload.SHA256) {
		return fmt.Errorf("dataset: payload sha256 is not a 64-hex digest")
	}
	if m.Payload.SizeBytes <= 0 {
		return fmt.Errorf("dataset: payload size_bytes must be positive, got %d", m.Payload.SizeBytes)
	}
	if m.Payload.Records <= 0 {
		return fmt.Errorf("dataset: payload records must be positive, got %d", m.Payload.Records)
	}
	if m.Rows.Observations != m.Payload.Records {
		return fmt.Errorf("dataset: rows.observations (%d) must equal payload.records (%d)",
			m.Rows.Observations, m.Payload.Records)
	}
	if len(m.Provenance) == 0 {
		return fmt.Errorf("dataset: provenance summary is empty — a dataset without provenance is refused")
	}
	seen := map[string]bool{}
	for _, p := range m.Provenance {
		if p.Source == "" || p.Connector == "" {
			return fmt.Errorf("dataset: provenance entry with empty source or connector")
		}
		if seen[p.Source] {
			return fmt.Errorf("dataset: provenance entry %q appears twice", p.Source)
		}
		seen[p.Source] = true
	}
	if m.Freshness.OldestObservedAt.IsZero() || m.Freshness.NewestObservedAt.IsZero() {
		return fmt.Errorf("dataset: freshness window is missing")
	}
	if m.Freshness.NewestObservedAt.Before(m.Freshness.OldestObservedAt) {
		return fmt.Errorf("dataset: freshness window is inverted (newest before oldest)")
	}
	if m.ValidatorVersion == "" {
		return fmt.Errorf("dataset: validator_version is missing")
	}
	return nil
}

// ValidateManifestURL enforces the transport rule: https always; plain
// http ONLY for loopback hosts (local testing).
func ValidateManifestURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("dataset: manifest URL must be absolute: %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("dataset: plain http is accepted only for loopback hosts (use https): %q", raw)
	default:
		return fmt.Errorf("dataset: manifest URL scheme must be https: %q", raw)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
