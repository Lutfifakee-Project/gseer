-- GSEER migration 0019_scan_concurrency_leases.down.sql — reverse of
-- the v0.3.2 security-microfix lease surface: drop the transient lease
-- table and remove the corrected-semantics column comments (restoring
-- the 0018 comment-free state).
--
-- Dropping scan_leases removes the max_concurrency cross-process
-- enforcement surface; the gateway's other default-deny controls
-- (scope matching, protocol/port gates, audit fail-closed) are
-- unaffected.

DROP TABLE IF EXISTS public.scan_leases;

COMMENT ON COLUMN public.scopes.max_total_bytes IS NULL;
COMMENT ON COLUMN public.scopes.max_concurrency IS NULL;
