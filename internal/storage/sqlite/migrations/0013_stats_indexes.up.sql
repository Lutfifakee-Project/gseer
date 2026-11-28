-- GSEER migration 0013_stats_indexes.up.sql — R44: make the per-search
-- index-metadata query (searchlite Stats, WithStats=true on every CLI
-- search) scale.  Measured at 1M assets / 1.23M observations: the
-- fixture-provenance count full-scanned observations and
-- max(observed_at) had no usable index, adding ~400 ms to EVERY search.
--
--   ix_observations_fixture  — partial index for the fixture-provenance
--                              count (count rides the tiny index).
--   ix_observations_observed_at — serves max(observed_at) instantly.

CREATE INDEX ix_observations_fixture    ON observations (provenance) WHERE provenance = 'fixture';
CREATE INDEX ix_observations_observed_at ON observations (observed_at);
