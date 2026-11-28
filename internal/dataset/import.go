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

package dataset

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// ImportMarkerSuffix is the pre-import snapshot's suffix (same directory
// as the live database — the restore is a same-directory rename).
const ImportMarkerSuffix = ".dataset-import-backup"

// ProvenanceDataset marks the dataset-import bookkeeping source row:
// "how this evidence ARRIVED".  The payload's per-record source names
// preserve "how it was COLLECTED".
const ProvenanceDataset = "central-dataset"

// ImportSourceName is the bookkeeping data_sources row for dataset
// installs (connector dataset-import, enabled=false — it is not a
// collectable connector).
const ImportSourceName = "central-dataset"

// ImportBatchSize bounds one IngestFacts call.
const ImportBatchSize = 200

// ImportOptions carries one import invocation.
type ImportOptions struct {
	// DBPath is the personal SQLite Local Index file (must exist).
	DBPath string
	// PayloadPath is the checksum-verified payload file (gzip NDJSON).
	PayloadPath string
	// Manifest is the validated manifest describing the payload.
	Manifest *Manifest
	// ManifestURL is the channel the manifest came from (recorded in
	// the install state).
	ManifestURL string
}

// ImportResult reports one completed import.
type ImportResult struct {
	Manifest *Manifest
	Stats    storage.IngestStats
	// Recovered is true when an interrupted import's snapshot was
	// restored before this import ran.
	Recovered bool
}

// Import runs the ATOMIC dataset import:
//
//  1. recover: a leftover snapshot from an interrupted import is
//     restored first (the previous import never half-landed);
//  2. snapshot: VACUUM INTO <db>.dataset-import-backup (byte-identical
//     pre-import image, fsynced by SQLite);
//  3. stream: every payload record is validated and ingested through
//     the SAME path every other writer uses (IngestFacts: suppression
//     gate, delivery-identity dedupe, per-source provenance);
//  4. verify: the streamed record count must equal the manifest's;
//  5. on ANY error: the live database is replaced by the snapshot
//     (same-directory rename) — all-or-nothing;
//  6. on success: the snapshot is removed and the install is recorded
//     (collection_jobs stats carry the version, counts, and checksum).
func Import(ctx context.Context, opts ImportOptions) (*ImportResult, error) {
	if opts.Manifest == nil {
		return nil, fmt.Errorf("dataset: import requires a manifest")
	}

	res, err := sqlite.Open(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("E_DB_UNAVAILABLE: cannot open the Local Index: %w", err)
	}
	db := res.DB
	snapshot := opts.DBPath + ImportMarkerSuffix

	// 1. Recovery: an interrupted import never half-landed — restore
	// its snapshot before doing anything else.
	recovered, err := recoverInterrupted(snapshot, opts.DBPath, db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if recovered {
		// Reopen on the restored file (the restore replaced it).
		_ = db.Close()
		res, err = sqlite.Open(opts.DBPath)
		if err != nil {
			return nil, fmt.Errorf("E_DB_UNAVAILABLE: cannot reopen the Local Index after recovery: %w", err)
		}
		db = res.DB
	}

	// 2. Snapshot (VACUUM INTO requires the target to not exist).  The
	// snapshot IS a full copy of the database — it carries the SQ-04
	// 0600 permission policy (the restore path refuses permissive
	// modes, defense in depth).
	_ = os.Remove(snapshot)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("dataset: cannot take the pre-import snapshot: %w", err)
	}
	if err := os.Chmod(snapshot, 0o600); err != nil {
		_ = db.Close()
		_ = os.Remove(snapshot)
		return nil, fmt.Errorf("dataset: cannot enforce the snapshot permission policy: %w", err)
	}

	// 3+4. Stream, ingest, verify.  Any failure restores the snapshot.
	result, ingestErr := streamAndIngest(ctx, db, opts)
	if result != nil {
		result.Recovered = recovered
	}
	if ingestErr != nil {
		_ = db.Close()
		if rerr := restoreSnapshot(snapshot, opts.DBPath); rerr != nil {
			return nil, fmt.Errorf("dataset: import failed (%v) AND the rollback failed: %v\n"+
				"Recover manually: mv %s %s", ingestErr, rerr, snapshot, opts.DBPath)
		}
		return nil, fmt.Errorf("dataset: import failed — the database was rolled back to the pre-import state: %w", ingestErr)
	}

	// 6. Record the install (after the data is committed; if THIS fails
	// the data is still consistent — the next update simply re-imports,
	// which is idempotent by delivery identity).
	if serr := recordInstall(ctx, db, opts, result); serr != nil {
		_ = db.Close()
		_ = os.Remove(snapshot)
		return result, fmt.Errorf("dataset: import succeeded but recording the install state failed: %w", serr)
	}
	_ = db.Close()
	if err := os.Remove(snapshot); err != nil && !os.IsNotExist(err) {
		return result, fmt.Errorf("dataset: import succeeded but the snapshot cleanup failed: %w", err)
	}
	return result, nil
}

// recoverInterrupted restores a leftover snapshot.  It only acts when
// the marker file exists (a previous import died before completing).
func recoverInterrupted(snapshot, dbPath string, db *sql.DB) (bool, error) {
	if _, err := os.Stat(snapshot); err != nil {
		return false, nil // no leftover — nothing to recover
	}
	if err := db.Close(); err != nil {
		return false, fmt.Errorf("dataset: cannot close the database for recovery: %w", err)
	}
	if err := restoreSnapshot(snapshot, dbPath); err != nil {
		return false, fmt.Errorf("dataset: an interrupted import left a snapshot; automatic recovery failed: %v\n"+
			"Recover manually: mv %s %s", err, snapshot, dbPath)
	}
	return true, nil
}

// restoreSnapshot replaces the live database with the snapshot
// (same-directory rename = atomic per step) and verifies the restored
// file opens with a SQLite integrity check.
func restoreSnapshot(snapshot, dbPath string) error {
	st, err := os.Stat(snapshot)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o177 != 0 {
		return fmt.Errorf("snapshot has permissive mode %04o — refusing to install it", uint32(st.Mode().Perm()))
	}
	if err := os.Rename(snapshot, dbPath); err != nil {
		return err
	}
	// The stale -wal/-shm sidecars of the REPLACED database belong to the
	// OLD image — replaying them against the restored main file would
	// resurrect pre-restore pages (the exact hazard the `db restore`
	// contract documents).  Remove them with the restore.
	for _, sidecar := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(sidecar); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot remove the stale sidecar %s: %w", sidecar, err)
		}
	}
	// Integrity check on the restored image (read-only open).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("restored database cannot be opened: %w", err)
	}
	defer func() { _ = db.Close() }()
	var check string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil {
		return fmt.Errorf("restored database integrity check failed: %w", err)
	}
	if check != "ok" {
		return fmt.Errorf("restored database failed the integrity check: %s", check)
	}
	return nil
}

// streamAndIngest streams the payload records and ingests them through
// the store, verifying the streamed count against the manifest.
func streamAndIngest(ctx context.Context, db *sql.DB, opts ImportOptions) (*ImportResult, error) {
	store := sqlite.NewStore(db)

	// Resolve the payload filename defensively (the manifest is
	// validated; this guards against misuse in tests).
	if !strings.HasSuffix(opts.PayloadPath, ".ndjson.gz") {
		return nil, fmt.Errorf("dataset: payload path %q is not a .ndjson.gz payload", opts.PayloadPath)
	}

	payload, err := os.Open(opts.PayloadPath) // #nosec G304 -- verified temp artifact from the dataset fetcher
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot open the verified payload: %w", err)
	}
	defer func() { _ = payload.Close() }()
	gz, err := gzip.NewReader(payload)
	if err != nil {
		return nil, fmt.Errorf("dataset: payload is not valid gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	dec := json.NewDecoder(gz)
	dec.DisallowUnknownFields()

	// The bookkeeping source row + the per-record source registry map
	// (dataset source rows are enabled=false — they are provenance
	// records, not collectable connectors).
	importSrcID, err := ensureImportSource(ctx, store)
	if err != nil {
		return nil, err
	}
	sourceIDs := map[string]int64{}
	ensureRecordSource := func(rec *Record) (int64, error) {
		if id, ok := sourceIDs[rec.Observation.Source]; ok {
			return id, nil
		}
		id, err := store.EnsureSource(ctx, rec.Observation.Source, rec.Observation.Connector,
			"central internet-asset dataset (docs/DATASET.md); evidence validated by the pipeline before publication",
			map[string]any{"channel": ProvenanceDataset, "dataset_version": opts.Manifest.DatasetVersion})
		if err != nil {
			return 0, fmt.Errorf("dataset: cannot register the dataset source %q: %w", rec.Observation.Source, err)
		}
		if err := store.SetSourceEnabled(ctx, rec.Observation.Source, false); err != nil {
			return 0, fmt.Errorf("dataset: cannot keep the dataset source %q disabled: %w", rec.Observation.Source, err)
		}
		sourceIDs[rec.Observation.Source] = id
		return id, nil
	}

	result := &ImportResult{Manifest: opts.Manifest}
	batch := make([]storage.Fact, 0, ImportBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		st, err := store.IngestFacts(ctx, batch)
		if err != nil {
			return err
		}
		result.Stats.AssetsInserted += st.AssetsInserted
		result.Stats.AssetsUpdated += st.AssetsUpdated
		result.Stats.ServicesInserted += st.ServicesInserted
		result.Stats.ServicesUpdated += st.ServicesUpdated
		result.Stats.ObservationsInserted += st.ObservationsInserted
		result.Stats.ObservationsDeduped += st.ObservationsDeduped
		result.Stats.Suppressed += st.Suppressed
		batch = batch[:0]
		return nil
	}

	var streamed int64
	for {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("dataset: record %d does not parse: %w", streamed+1, err)
		}
		streamed++
		fact, err := buildFact(&rec, streamed, opts.Manifest.DatasetVersion)
		if err != nil {
			return nil, err
		}
		srcID, err := ensureRecordSource(&rec)
		if err != nil {
			return nil, err
		}
		fact.Observation.SourceID = srcID
		stampDeliveryID(&fact, srcID, opts.Manifest.DatasetVersion, streamed)
		batch = append(batch, fact)
		if len(batch) >= ImportBatchSize {
			if err := flush(); err != nil {
				return nil, fmt.Errorf("dataset: ingestion failed at record %d: %w", streamed, err)
			}
		}
	}
	if err := flush(); err != nil {
		return nil, fmt.Errorf("dataset: ingestion failed on the final batch: %w", err)
	}

	// 4. Count verification: the streamed record count must equal the
	// manifest's — a truncated or padded payload is refused.
	if streamed != opts.Manifest.Payload.Records {
		return nil, fmt.Errorf("dataset: record count mismatch: manifest says %d records, payload streamed %d",
			opts.Manifest.Payload.Records, streamed)
	}
	_ = importSrcID
	return result, nil
}

// buildFact validates one dataset record and converts it to the
// ingestion unit.  Validation is the LAST gate before the suppression
// rules: a malformed record aborts the whole import (rollback).
func buildFact(rec *Record, seq int64, datasetVersion int64) (storage.Fact, error) {
	if rec.Schema != SchemaVersion {
		return storage.Fact{}, fmt.Errorf("dataset: record %d has schema %d, want %d", seq, rec.Schema, SchemaVersion)
	}
	if err := validateAsset(&rec.Asset); err != nil {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: %w", seq, err)
	}
	asset := storage.Asset{
		Kind:       storage.AssetKind(rec.Asset.Kind),
		Value:      rec.Asset.Value,
		IP:         rec.Asset.IP,
		Domain:     rec.Asset.Domain,
		Hostname:   rec.Asset.Hostname,
		ASN:        rec.Asset.ASN,
		ASNOrg:     rec.Asset.ASNOrg,
		GeoCountry: rec.Asset.GeoCountry,
		GeoRegion:  rec.Asset.GeoRegion,
		GeoCity:    rec.Asset.GeoCity,
		Sources:    rec.Asset.Sources,
	}
	var svc *storage.Service
	if rec.Service != nil {
		if err := validateService(rec.Service); err != nil {
			return storage.Fact{}, fmt.Errorf("dataset: record %d: %w", seq, err)
		}
		svc = &storage.Service{
			Port:      rec.Service.Port,
			Transport: rec.Service.Transport,
			Protocol:  rec.Service.Protocol,
			Name:      rec.Service.Name,
			Product:   rec.Service.Product,
			Version:   rec.Service.Version,
		}
	}
	if rec.Observation.Source == "" || rec.Observation.Connector == "" {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: observation source/connector is empty", seq)
	}
	if rec.Observation.ObservedAt.IsZero() {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: observed_at is missing", seq)
	}
	if rec.Observation.ObservedAt.After(time.Now().Add(MaxFutureSkew)) {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: observed_at is more than %s in the future", seq, MaxFutureSkew)
	}
	if rec.Observation.PayloadHash == "" {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: payload_hash is missing (the L2 identity must come from the collector)", seq)
	}
	if rec.Observation.Provenance == "" {
		return storage.Fact{}, fmt.Errorf("dataset: record %d: provenance is missing", seq)
	}

	// Deterministic delivery identity, stamped user-locally (the mirror
	// of the collect runner's per-delivery stamping): cursor =
	// sha256("v1|dataset:<version>|rec:<seq>"); id = fnv1a-64 over
	// "dataset:<source_id>:<cursor>" (source_id is resolved by the
	// caller right after this).  Same dataset version re-imported ⇒
	// same cursors ⇒ the L1 dedupe collapses everything (idempotent).
	cursor := deliveryCursor(datasetVersion, seq)
	obs := storage.Observation{
		// ID is stamped by the caller once the source id is known.
		SourceCursor: cursor,
		ObservedAt:   rec.Observation.ObservedAt.UTC(),
		PayloadHash:  rec.Observation.PayloadHash,
		Provenance:   rec.Observation.Provenance,
		Evidence:     rec.Observation.Evidence,
	}
	if obs.Evidence == nil {
		obs.Evidence = map[string]any{}
	}
	obs.Evidence["dataset_version"] = datasetVersion
	return storage.Fact{Asset: asset, Service: svc, Observation: obs}, nil
}

// stampDeliveryID derives the caller-assigned observations.id the same
// way the collect runner does (fnv1a-64, positive; collisions land in
// the L1/L2 dedupe path, never in correctness).  The id is derived from
// the USER-LOCAL source id + the deterministic dataset cursor, so a
// re-import of the same dataset version stamps identical identities
// (idempotent) and never collides with a store's unrelated rows beyond
// the dedupe contract.
func stampDeliveryID(f *storage.Fact, sourceID int64, datasetVersion int64, seq int64) {
	cursor := deliveryCursor(datasetVersion, seq)
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "dataset:%d:%s", sourceID, cursor)
	f.Observation.ID = int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}

// deliveryCursor derives one record's L1 cursor (deterministic across
// re-imports of the same dataset version).
func deliveryCursor(datasetVersion, seq int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("v1|dataset:%d|rec:%d", datasetVersion, seq)))
	return hex.EncodeToString(sum[:])
}

// validateAsset enforces the asset contract.
func validateAsset(a *RecordAsset) error {
	switch storage.AssetKind(a.Kind) {
	case storage.AssetKindDomain, storage.AssetKindIP, storage.AssetKindHostname:
	default:
		return fmt.Errorf("asset kind %q is not a known kind", a.Kind)
	}
	if strings.TrimSpace(a.Value) == "" {
		return fmt.Errorf("asset value is empty")
	}
	if storage.AssetKind(a.Kind) == storage.AssetKindIP {
		if net.ParseIP(a.Value) == nil {
			return fmt.Errorf("asset value %q is not a valid IP", a.Value)
		}
	}
	return nil
}

// validateService enforces the service contract (port evidence).
func validateService(s *RecordService) error {
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("service port %d is out of range", s.Port)
	}
	switch s.Transport {
	case "tcp", "udp":
	default:
		return fmt.Errorf("service transport %q is not tcp|udp", s.Transport)
	}
	if strings.TrimSpace(s.Protocol) == "" {
		return fmt.Errorf("service protocol is empty")
	}
	return nil
}

// ensureImportSource upserts the bookkeeping `central-dataset` row
// (enabled=false — not a collectable connector).
func ensureImportSource(ctx context.Context, store *sqlite.Store) (int64, error) {
	id, err := store.EnsureSource(ctx, ImportSourceName, "dataset-import",
		"central internet-asset dataset channel (docs/DATASET.md); records validated by the pipeline before publication; imported through the standard ingestion path",
		map[string]any{"channel": ProvenanceDataset})
	if err != nil {
		return 0, fmt.Errorf("dataset: cannot register the %s source row: %w", ImportSourceName, err)
	}
	if err := store.SetSourceEnabled(ctx, ImportSourceName, false); err != nil {
		return 0, fmt.Errorf("dataset: cannot keep %s disabled: %w", ImportSourceName, err)
	}
	return id, nil
}

// recordInstall records the completed import as a collection_jobs row
// on the central-dataset source (kind 'fetch' — the job bookkeeping
// schema's existing kind; the stats JSON carries the dataset facts).
// A lost state row is harmless: the next update re-imports idempotently.
func recordInstall(ctx context.Context, db *sql.DB, opts ImportOptions, result *ImportResult) error {
	var srcID int64
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM data_sources WHERE name = ?`, ImportSourceName).Scan(&srcID); err != nil {
		return fmt.Errorf("dataset: cannot resolve the install-state source row: %w", err)
	}
	store := sqlite.NewStore(db)
	jobID, err := store.StartCollectionJob(ctx, srcID, "fetch")
	if err != nil {
		return fmt.Errorf("dataset: cannot start the install-state job: %w", err)
	}
	stats := map[string]any{
		"dataset_version":    opts.Manifest.DatasetVersion,
		"manifest_url":       opts.ManifestURL,
		"payload_sha256":     opts.Manifest.Payload.SHA256,
		"records":            opts.Manifest.Payload.Records,
		"assets":             opts.Manifest.Rows.Assets,
		"services":           opts.Manifest.Rows.Services,
		"observations":       opts.Manifest.Rows.Observations,
		"ingested":           result.Stats.ObservationsInserted,
		"deduped":            result.Stats.ObservationsDeduped,
		"suppressed":         result.Stats.Suppressed,
		"oldest_observed_at": opts.Manifest.Freshness.OldestObservedAt.UTC().Format(time.RFC3339),
		"newest_observed_at": opts.Manifest.Freshness.NewestObservedAt.UTC().Format(time.RFC3339),
		"generated_at_utc":   opts.Manifest.GeneratedAtUTC.UTC().Format(time.RFC3339),
	}
	if err := store.FinishCollectionJob(ctx, jobID, "success", stats, ""); err != nil {
		return fmt.Errorf("dataset: cannot record the install-state job: %w", err)
	}
	return nil
}
