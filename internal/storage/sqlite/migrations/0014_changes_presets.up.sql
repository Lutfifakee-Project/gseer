-- GSEER migration 0014_changes_presets.up.sql — R56/R57/R60: historical
-- change detection and saved-query presets.
--
-- asset_changes — R57 searchable change events.  Events are produced by
-- the `changes detect` component (internal/changes), NOT by the ingest
-- path: detection walks observations grouped per asset and emits an event
-- only when a projected value ACTUALLY DIFFERS from the previous state —
-- routine refreshes of unchanged data emit nothing.  Provenance is the
-- observation that revealed the change (source_id + provenance + the
-- observation's observed_at).  The UNIQUE tuple makes detection
-- idempotent: re-running the detector for the same assets re-derives the
-- same events and inserts nothing new.
CREATE TABLE asset_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    service_id  INTEGER,
    change_kind TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    source_id   INTEGER NOT NULL,
    provenance  TEXT NOT NULL
);
CREATE UNIQUE INDEX ux_asset_changes_event ON asset_changes
    (asset_id, COALESCE(service_id, 0), change_kind, observed_at, new_value);
CREATE INDEX ix_asset_changes_asset ON asset_changes (asset_id, observed_at DESC);
CREATE INDEX ix_asset_changes_kind  ON asset_changes (change_kind, observed_at DESC);
CREATE INDEX ix_asset_changes_time  ON asset_changes (observed_at DESC);

-- search_presets — R60 saved queries (name → GQL + sort + mode), CLI-first.
CREATE TABLE search_presets (
    name       TEXT PRIMARY KEY,
    gql        TEXT NOT NULL,
    sort       TEXT,
    mode       TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- detect_checkpoints — R57 incremental detection state (which observation
-- id the detector has consumed).  Corrupt/missing checkpoint = full
-- re-detect (idempotent via the UNIQUE tuple), never silent data loss.
-- detect_seen — the exact set of observation ids the detector has
-- consumed.  observations.id is CALLER-SUPPLIED (hash-derived for the
-- fixture/bench/import writers), so a monotonic id checkpoint cannot
-- detect imported/backfilled data; the processed-set marker handles any
-- id pattern (R57: no silently-missed ingestion).
CREATE TABLE detect_seen (
    obs_id INTEGER PRIMARY KEY
);

CREATE TABLE detect_checkpoints (
    name       TEXT PRIMARY KEY,
    last_obs_id INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
