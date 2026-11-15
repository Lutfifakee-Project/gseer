-- GSEER migration 0020_scan_lease_tokens.down.sql — reverse of the
-- lease-token column: drop it (the column comment drops with the
-- column).  Holding leases across the downgrade window is not
-- supported; running observations should be finished first.

ALTER TABLE scan_leases DROP COLUMN IF EXISTS token;
