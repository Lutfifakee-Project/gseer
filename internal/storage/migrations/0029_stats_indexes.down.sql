-- 0029 down — drop the R44 stats indexes.

DROP INDEX IF EXISTS ix_observations_observed_at;
DROP INDEX IF EXISTS ix_observations_fixture;
