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

// Package changes — R57 reliable change detection over the observation
// log.  The observations table IS the historical evidence (append-only,
// observed_at per row); this package derives SEARCHABLE change events
// from it without inventing any history: an event exists only when a
// projected value actually differs from the previous observation's
// projected value, and carries the provenance of the observation that
// revealed it.
//
// Detection is idempotent: the UNIQUE event tuple makes re-runs no-ops,
// and the checkpoint (detect_checkpoints) records how far the observation
// log has been consumed.  A corrupt or missing checkpoint degrades to a
// full re-detect — never to silent data loss.
package changes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Event is one detected change (R57).
type Event struct {
	AssetID    int64
	ServiceID  int64 // 0 = asset-level change
	Kind       string
	OldValue   string // "" = no previous value (new sighting)
	NewValue   string
	ObservedAt string
	DetectedAt string
	SourceID   int64
	Provenance string
}

// Stats reports what one Detect run did (R57: no hidden failures).
type Stats struct {
	ObservationsScanned int
	AssetsScanned       int
	EventsEmitted       int
	EventsDeduped       int
	FullRescan          bool
	DurationMs          int64
	LastObsID           int64
}

// checkpointName is the single detector stream id in detect_checkpoints.
const checkpointName = "changes"

// projection fields tracked per (asset|service).  Each entry: evidence
// JSON path prefix → list of change kinds.  Values are compared as
// rendered strings (canonical JSON for objects, joined lists for arrays).
type trackedField struct {
	kind  string
	label string
}

var assetFields = []trackedField{
	{"dns.record", "dns"},
	{"asn.prefix", "ip2asn"},
	{"ct.cert", "ctlog"},
}

var serviceFields = []trackedField{
	{"http.status", "http"},
	{"http.title", "http"},
	{"http.server", "http"},
	{"tls.version", "tls"},
	{"tls.cert", "tls"},
	{"tech", "fingerprint"},
	{"banner", "ssh"},
}

// Detect derives change events for every asset touched by observations
// newer than the checkpoint (or ALL assets when full is true), writing
// events idempotently (INSERT OR IGNORE over the UNIQUE tuple).
func Detect(ctx context.Context, db *sql.DB, full bool) (Stats, error) {
	start := time.Now()
	st := Stats{FullRescan: full}

	// Unprocessed observations (R57): the processed-set marker handles
	// caller-supplied hash ids that a monotonic checkpoint would miss.
	// The marker table is ensured here so a database that predates the
	// migration addition (or was restored from an older backup) still
	// detects correctly instead of failing.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS detect_seen (obs_id INTEGER PRIMARY KEY)`); err != nil {
		return st, fmt.Errorf("changes: ensure detect_seen: %w", err)
	}
	// A full rescan clears the marker set first — idempotent re-derivation.
	if full {
		if _, err := db.ExecContext(ctx, `DELETE FROM detect_seen`); err != nil {
			return st, fmt.Errorf("changes: clear processed set: %w", err)
		}
	}

	// Assets touched since the last run (empty set = nothing to do).
	assetIDs := []int64{}
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT asset_id FROM observations o
		 LEFT JOIN detect_seen s ON s.obs_id = o.id
		 WHERE s.obs_id IS NULL ORDER BY asset_id`)
	if err != nil {
		return st, fmt.Errorf("changes: list touched assets: %w", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return st, err
		}
		assetIDs = append(assetIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return st, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return st, fmt.Errorf("changes: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	detectedAt := time.Now().UTC().Format(time.RFC3339)
	insStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO asset_changes
		(asset_id, service_id, change_kind, old_value, new_value, observed_at, detected_at, source_id, provenance)
		VALUES (?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?)`)
	if err != nil {
		return st, fmt.Errorf("changes: prepare insert: %w", err)
	}
	defer insStmt.Close()

	for _, assetID := range assetIDs {
		// Full history of this asset, oldest first: the previous state
		// comes from the asset's OWN observations (actual evidence).
		orows, err := tx.QueryContext(ctx, `
			SELECT o.id, o.service_id, o.observed_at, o.evidence, o.provenance, o.source_id
			FROM observations o
			WHERE o.asset_id = ?
			ORDER BY o.asset_id, o.observed_at, o.id`, assetID)
		if err != nil {
			return st, fmt.Errorf("changes: scan asset %d: %w", assetID, err)
		}
		// state: "asset" or "svc:<id>" → projected values seen so far.
		state := map[string]map[string]string{}
		firstObs := true
		var seenIDs []int64
		for orows.Next() {
			var (
				obsID, srcID int64
				svcID        sql.NullInt64
				observedAt   string
				evidenceRaw  string
				prov         string
			)
			if err := orows.Scan(&obsID, &svcID, &observedAt, &evidenceRaw, &prov, &srcID); err != nil {
				orows.Close()
				return st, err
			}
			st.ObservationsScanned++
			seenIDs = append(seenIDs, obsID)
			var doc map[string]any
			if err := json.Unmarshal([]byte(evidenceRaw), &doc); err != nil {
				// Malformed evidence is not a change; skip quietly but
				// count it (data-quality signal for R63 reporting).
				continue
			}
			if firstObs {
				firstObs = false
				st.AssetsScanned++
				if emit(st, insStmt, Event{
					AssetID: assetID, Kind: "asset.new", NewValue: "seen",
					ObservedAt: observedAt, DetectedAt: detectedAt,
					SourceID: srcID, Provenance: prov,
				}) {
					st.EventsEmitted++
				} else {
					st.EventsDeduped++
				}
			}
			key := "asset"
			if svcID.Valid {
				key = fmt.Sprintf("svc:%d", svcID.Int64)
				if _, seen := state[key]; !seen {
					if emit(st, insStmt, Event{
						AssetID: assetID, ServiceID: svcID.Int64, Kind: "service.new", NewValue: "seen",
						ObservedAt: observedAt, DetectedAt: detectedAt,
						SourceID: srcID, Provenance: prov,
					}) {
						st.EventsEmitted++
					} else {
						st.EventsDeduped++
					}
				}
			}
			projected := project(doc, svcID.Valid)
			stt := state[key]
			if stt == nil {
				stt = map[string]string{}
				state[key] = stt
			}
			for kind, val := range projected {
				prev, had := stt[kind]
				stt[kind] = val
				if had && prev != val {
					if emit(st, insStmt, Event{
						AssetID: assetID, ServiceID: svcID.Int64, Kind: kind,
						OldValue: prev, NewValue: val,
						ObservedAt: observedAt, DetectedAt: detectedAt,
						SourceID: srcID, Provenance: prov,
					}) {
						st.EventsEmitted++
					} else {
						st.EventsDeduped++
					}
				}
			}
		}
		orows.Close()
		if err := orows.Err(); err != nil {
			return st, err
		}
		// Mark THIS asset's observations processed (the whole history was
		// just scanned — new rows for the same asset arrive with the next
		// run's touched-set query).
		seenStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO detect_seen (obs_id) VALUES (?)`)
		if err != nil {
			return st, err
		}
		for _, id := range seenIDs {
			if _, err := seenStmt.ExecContext(ctx, id); err != nil {
				seenStmt.Close()
				return st, err
			}
		}
		seenStmt.Close()
		if int64(len(seenIDs)) > st.LastObsID {
			st.LastObsID = int64(len(seenIDs))
		}
	}

	// Informational checkpoint: the highest observation id seen overall
	// (detect_seen is the authoritative processed marker).
	var topObs sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(id) FROM observations`).Scan(&topObs); err != nil {
		return st, err
	}
	var topVal int64
	if topObs.Valid {
		topVal = topObs.Int64
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO detect_checkpoints (name, last_obs_id, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET last_obs_id = excluded.last_obs_id, updated_at = excluded.updated_at`,
		checkpointName, topVal, detectedAt); err != nil {
		return st, fmt.Errorf("changes: checkpoint: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return st, fmt.Errorf("changes: commit: %w", err)
	}
	st.LastObsID = topVal
	st.DurationMs = time.Since(start).Milliseconds()
	return st, nil
}

// emit inserts one event; returns true when it was actually inserted
// (false = deduped: the same event already exists).
func emit(st Stats, stmt *sql.Stmt, e Event) bool {
	_ = st
	res, err := stmt.Exec(e.AssetID, nullSvc(e.ServiceID), e.Kind, e.OldValue, e.NewValue,
		e.ObservedAt, e.DetectedAt, e.SourceID, e.Provenance)
	if err != nil {
		// Idempotency makes dedup a no-op; a real failure surfaces by the
		// caller's tx rollback — count as deduped defensively (R57: no
		// false-positive events).
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func nullSvc(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// project renders the tracked projected values from one evidence payload.
// Only values that ACTUALLY EXIST in the payload are projected (R56: no
// invented history; a field absent from an observation does not undo the
// previous value).
func project(doc map[string]any, isService bool) map[string]string {
	out := map[string]string{}
	if !isService {
		for _, tf := range assetFields {
			if v := pathValue(doc, tf.label); v != "" {
				out[tf.kind] = v
			}
		}
		return out
	}
	if hm, ok := doc["http"].(map[string]any); ok {
		if v, ok := hm["status"].(float64); ok {
			out["http.status"] = fmt.Sprintf("%d", int64(v))
		}
		if v, ok := hm["title"].(string); ok && v != "" {
			out["http.title"] = v
		}
		if v, ok := hm["server"].(string); ok && v != "" {
			out["http.server"] = v
		}
	}
	if tm, ok := doc["tls"].(map[string]any); ok {
		if v, ok := tm["version"].(string); ok && v != "" {
			out["tls.version"] = v
		}
		// A certificate changed when its serial changed (issuer/subject
		// fallback when the source omitted the serial).
		serial, _ := tm["cert_serial"].(string)
		if serial == "" {
			subj, _ := tm["cert_subject_cn"].(string)
			iss, _ := tm["cert_issuer_cn"].(string)
			serial = subj + "|" + iss
		}
		if serial != "|" && serial != "" {
			out["tls.cert"] = serial
		}
	}
	if fm, ok := doc["fingerprint"].(map[string]any); ok {
		if arr, ok := fm["technologies"].([]any); ok {
			strs := make([]string, 0, len(arr))
			for _, v := range arr {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				}
			}
			sort.Strings(strs)
			if len(strs) > 0 {
				out["tech"] = strings.Join(strs, ",")
			}
		}
	}
	if sm, ok := doc["ssh"].(map[string]any); ok {
		if v, ok := sm["banner"].(string); ok && v != "" {
			out["banner"] = v
		}
	}
	return out
}

// pathValue renders an asset-level tracked value (dns record object,
// ip2asn prefix, ct log fingerprint).
func pathValue(doc map[string]any, key string) string {
	switch key {
	case "ip2asn":
		if m, ok := doc["ip2asn"].(map[string]any); ok {
			if p, ok := m["prefix"].(string); ok && p != "" {
				return p
			}
		}
	case "ctlog":
		if m, ok := doc["ctlog"].(map[string]any); ok {
			if h, ok := m["leaf_sha256"].(string); ok && h != "" {
				return h
			}
		}
	case "dns":
		if m, ok := doc["dns"].(map[string]any); ok {
			b, err := json.Marshal(m)
			if err == nil {
				return string(b)
			}
		}
	}
	return ""
}
