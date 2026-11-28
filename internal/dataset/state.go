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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// State reports the LAST SUCCESSFUL dataset import recorded in the
// Local Index (the collection_jobs stats of the central-dataset source).
// A missing state simply means "never imported" — never an error.
type State struct {
	Installed        bool
	DatasetVersion   int64
	ImportedAt       time.Time
	ManifestURL      string
	PayloadSHA256    string
	Records          int64
	Ingested         int64
	Deduped          int64
	Suppressed       int64
	OldestObservedAt time.Time
	NewestObservedAt time.Time
	GeneratedAtUTC   time.Time
}

// LoadState reads the install state from the Local Index.
func LoadState(ctx context.Context, db *sql.DB) (*State, error) {
	var statsRaw string
	var finished sql.NullString
	err := db.QueryRowContext(ctx, `
SELECT cj.stats, cj.finished_at
FROM collection_jobs cj
JOIN data_sources ds ON ds.id = cj.source_id
WHERE ds.name = ? AND cj.status = 'success'
ORDER BY cj.id DESC
LIMIT 1`, ImportSourceName).Scan(&statsRaw, &finished)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return &State{}, nil // never imported
	default:
		return nil, fmt.Errorf("dataset: cannot read the install state: %w", err)
	}
	var stats map[string]any
	if err := json.Unmarshal([]byte(statsRaw), &stats); err != nil {
		return nil, fmt.Errorf("dataset: install-state stats do not parse: %w", err)
	}
	st := &State{Installed: true}
	st.DatasetVersion = jsonInt64(stats, "dataset_version")
	st.Records = jsonInt64(stats, "records")
	st.Ingested = jsonInt64(stats, "ingested")
	st.Deduped = jsonInt64(stats, "deduped")
	st.Suppressed = jsonInt64(stats, "suppressed")
	st.ManifestURL = jsonStr(stats, "manifest_url")
	st.PayloadSHA256 = jsonStr(stats, "payload_sha256")
	st.OldestObservedAt = jsonTime(stats, "oldest_observed_at")
	st.NewestObservedAt = jsonTime(stats, "newest_observed_at")
	st.GeneratedAtUTC = jsonTime(stats, "generated_at_utc")
	if finished.Valid && finished.String != "" {
		if t, perr := time.Parse(time.RFC3339, finished.String); perr == nil {
			st.ImportedAt = t
		} else if t2, perr2 := time.Parse("2006-01-02 15:04:05.999999999-07:00", finished.String); perr2 == nil {
			st.ImportedAt = t2
		}
	}
	return st, nil
}

func jsonInt64(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case string:
		var n int64
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	default:
		return 0
	}
}

func jsonStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func jsonTime(m map[string]any, key string) time.Time {
	if v, ok := m[key].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// HistoryEntry is one previously recorded successful dataset import.
// Because recordInstall appends a collection_jobs row per import, the
// install history IS the job history — no extra table, no schema churn;
// the newest row is the state LoadState reports.
type HistoryEntry struct {
	DatasetVersion int64
	ImportedAt     time.Time
	Records        int64
	Ingested       int64
	Deduped        int64
	Suppressed     int64
	PayloadSHA256  string
}

// LoadHistory reads the last `limit` successful dataset imports, newest
// first.  An empty list simply means "never imported" — never an error.
func LoadHistory(ctx context.Context, db *sql.DB, limit int) ([]HistoryEntry, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := db.QueryContext(ctx, `
SELECT cj.stats, cj.finished_at
FROM collection_jobs cj
JOIN data_sources ds ON ds.id = cj.source_id
WHERE ds.name = ? AND cj.status = 'success'
ORDER BY cj.id DESC
LIMIT ?`, ImportSourceName, limit)
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot read the install history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []HistoryEntry
	for rows.Next() {
		var statsRaw string
		var finished sql.NullString
		if err := rows.Scan(&statsRaw, &finished); err != nil {
			return nil, fmt.Errorf("dataset: cannot read an install-history row: %w", err)
		}
		var stats map[string]any
		if err := json.Unmarshal([]byte(statsRaw), &stats); err != nil {
			return nil, fmt.Errorf("dataset: install-history stats do not parse: %w", err)
		}
		e := HistoryEntry{
			DatasetVersion: jsonInt64(stats, "dataset_version"),
			Records:        jsonInt64(stats, "records"),
			Ingested:       jsonInt64(stats, "ingested"),
			Deduped:        jsonInt64(stats, "deduped"),
			Suppressed:     jsonInt64(stats, "suppressed"),
			PayloadSHA256:  jsonStr(stats, "payload_sha256"),
		}
		if finished.Valid && finished.String != "" {
			if t, perr := time.Parse(time.RFC3339, finished.String); perr == nil {
				e.ImportedAt = t
			} else if t2, perr2 := time.Parse("2006-01-02 15:04:05.999999999-07:00", finished.String); perr2 == nil {
				e.ImportedAt = t2
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dataset: install-history rows: %w", err)
	}
	return out, nil
}
