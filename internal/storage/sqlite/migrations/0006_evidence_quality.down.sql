-- 0006 down — drop the maintained evidence table (the search surface
-- loses evidence_kinds / last_observed / coverage_class; the raw
-- assets/observations data is untouched).

DROP TRIGGER IF EXISTS trg_asset_evidence_observation_insert;
DROP TRIGGER IF EXISTS trg_asset_evidence_sources_update;
DROP TRIGGER IF EXISTS trg_asset_evidence_insert;
DROP INDEX IF EXISTS ix_asset_evidence_class;
DROP TABLE IF EXISTS asset_evidence;
