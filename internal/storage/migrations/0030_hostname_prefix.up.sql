-- 0030 — hostname prefix search index (R113): the PostgreSQL twin of the
-- personal-mode migration 0015.  Same measured evidence: hostname
-- equality and PREFIX-LIKE patterns (`hostname == "api.*"` → LIKE
-- 'api%') full-scanned assets.
--
-- text_pattern_ops is required for the planner to use a btree index for
-- LIKE 'prefix%' on a text column whose default collation is not C.
-- Equality on hostname remains served by scans until real-workload
-- evidence justifies a second default-collation index; this migration
-- does not claim more than the measured problem.
CREATE INDEX ix_assets_hostname_prefix ON assets (hostname text_pattern_ops);

ANALYZE assets;
