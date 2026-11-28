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

package cli

// schedule.go — the per-source freshness contract (R35 P5, R36 P4):
// default refresh intervals per connector kind (overridable per source
// through the source config's "interval" value) and the last-success
// lookup the freshness views are computed from.  Purely informational:
// the scheduler stays operator-managed (`gseer collect run --source X`
// / `--all`), never time-triggered by the binary.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// scheduleDefaults are the freshness intervals per connector kind.
// ctlog publishes continuously (short interval); dns zones churn
// hourly; routeviews dumps several MRT files per day; the IP-to-ASN
// DNS mapping is the slowest-moving of the set.
var scheduleDefaults = map[string]time.Duration{
	"ctlog":      6 * time.Hour,
	"dns":        1 * time.Hour,
	"routeviews": 6 * time.Hour,
	"ip2asn":     24 * time.Hour,
	"ct":         6 * time.Hour,
	"ptr":        24 * time.Hour,
	"rdap":       168 * time.Hour,
}

// scheduleIntervalFor resolves a source's refresh interval: the config
// "interval" override (a Go duration string like "30m"/"12h") wins,
// otherwise the connector default; unknown connectors get 24h.
func scheduleIntervalFor(connector string, cfg []byte) time.Duration {
	if len(cfg) > 0 {
		var m map[string]any
		if json.Unmarshal(cfg, &m) == nil {
			if v, ok := m["interval"].(string); ok && strings.TrimSpace(v) != "" {
				if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
					return d
				}
			}
		}
	}
	if d, ok := scheduleDefaults[connector]; ok {
		return d
	}
	return 24 * time.Hour
}

// scheduleLastSuccess returns the most recent successful collection
// job's finish time for a source (zero time = never ran successfully).
func scheduleLastSuccess(ctx context.Context, db *sql.DB, sourceID int64) (time.Time, error) {
	var finished sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT MAX(finished_at) FROM collection_jobs WHERE source_id = ? AND status = 'success'`,
		sourceID).Scan(&finished)
	if err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("sqlite: cannot read the source's last success: %w", err)
	}
	if !finished.Valid || finished.String == "" {
		return time.Time{}, nil
	}
	t, perr := time.Parse(time.RFC3339Nano, finished.String)
	if perr != nil {
		return time.Time{}, nil // an unparsable stamp is a freshness miss, not a crash
	}
	return t, nil
}

// scheduleSourceStale reports whether a source is over its interval
// (or has never run — also stale: nothing collected yet).
func scheduleSourceStale(now time.Time, interval time.Duration, last time.Time) bool {
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= interval
}
