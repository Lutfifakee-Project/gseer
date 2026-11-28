-- GSEER migration 0029_stats_indexes.up.sql — R44: the PostgreSQL twin of
-- the personal-mode 0013 stats indexes.  The self-hosted Stats query
-- (internal/search service, WithStats=true on every CLI search) counts
-- fixture-provenance observations and takes max(observed_at); the same
-- indexes keep it linear-time-cheap at scale.

CREATE INDEX ix_observations_fixture     ON observations (provenance) WHERE provenance = 'fixture';
CREATE INDEX ix_observations_observed_at ON observations (observed_at);
