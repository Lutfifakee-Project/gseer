-- 0015 — hostname prefix search index (R113): measured evidence first.
--
-- Before this index, hostname equality and PREFIX-LIKE patterns
-- (`hostname == "api.*"` compiles to LIKE 'api%' ESCAPE '\') full-scanned
-- the assets table: EXPLAIN QUERY PLAN on the verified 1M-asset corpus
-- reported "SCAN assets" and a no-match equality probe cost ~98 ms.
-- ix_assets_domain_hostname (domain, hostname) cannot serve a pure
-- hostname predicate — hostname is its second column.
--
-- COLLATE NOCASE matters: SQLite's LIKE is case-insensitive for ASCII,
-- and the "LIKE optimization" lets the planner use a btree index for a
-- prefix pattern ONLY when the indexed column's collation is NOCASE.
-- Suffix / substring patterns ('%.example', '%api%') remain scans — that
-- is inherent to LIKE, not a gap.
CREATE INDEX ix_assets_hostname_nocase ON assets (hostname COLLATE NOCASE);

-- Refresh planner statistics so the new index is actually chosen.
ANALYZE;
