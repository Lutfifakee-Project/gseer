-- GSEER migration 0018_active_observation.down.sql — reverse of the up
-- migration (additive columns dropped, audit table dropped, the additive
-- runtime grants revoked).  Never run automatically except by
-- `gseer db migrate ... down` / golang-migrate force-recovery flows.

REVOKE SELECT, INSERT, UPDATE ON TABLE public.scopes      FROM gseer_app;
REVOKE SELECT, INSERT         ON TABLE public.scan_audits FROM gseer_app;

DROP TABLE IF EXISTS scan_audits;

ALTER TABLE scopes
    DROP COLUMN IF EXISTS protocols,
    DROP COLUMN IF EXISTS ports,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS max_concurrency,
    DROP COLUMN IF EXISTS max_requests,
    DROP COLUMN IF EXISTS max_total_bytes;
