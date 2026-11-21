// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

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
