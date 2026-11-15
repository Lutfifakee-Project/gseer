-- GSEER personal-mode migration 0004_scan_lease_tokens.up.sql — lease
-- ownership tokens for personal mode (1:1 port of the PostgreSQL 0020
-- contract, using the personal dialect; additive ALTER only).
--
-- Defect closed: the 0003 lease identity was the process-level holder
-- string ("hostname#pid"), identical for every observation in one
-- process, so a late-releasing observation could delete a newer
-- observation's lease on the same slot.  token (per-acquisition
-- 128-bit crypto/rand hex, storage.NewLeaseToken) is now the OWNERSHIP
-- identity: release matches (scope_id, slot, token); renewal extends
-- only the live row matching (scope_id, slot, token) and refuses
-- lapsed/stolen leases (storage.ErrLeaseLost — fatal: no new
-- connections).  holder remains diagnostic provenance only.
--
-- Pre-existing rows get '' and expire per the 0003 TTL like crashed
-- holders; no backfill is possible or needed.
--
-- schema_migrations is owned by the storage layer's migrate runner.

ALTER TABLE scan_leases ADD COLUMN token TEXT NOT NULL DEFAULT '';
