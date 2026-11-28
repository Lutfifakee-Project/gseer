-- 0014 down — drop the R56/R57/R60 tables.

DROP INDEX IF EXISTS ux_asset_changes_event;
DROP INDEX IF EXISTS ix_asset_changes_time;
DROP INDEX IF EXISTS ix_asset_changes_kind;
DROP INDEX IF EXISTS ix_asset_changes_asset;
DROP TABLE IF EXISTS detect_seen;
DROP TABLE IF EXISTS detect_checkpoints;
DROP TABLE IF EXISTS search_presets;
DROP TABLE IF EXISTS asset_changes;
