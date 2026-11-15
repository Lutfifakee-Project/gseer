-- GSEER migration 0020_scan_lease_tokens.up.sql — lease ownership
-- tokens (v0.3.2 FINAL security microfix, FIX B part 1).
--
-- Additive ONLY: one column on the transient scan_leases table created
-- by 0019.  Historical migrations are untouched.
--
-- Defect closed: the 0019 lease identity was the process-level holder
-- string ("hostname#pid"), identical for every observation in one
-- process.  Release matched (scope_id, slot, holder), so a late-
-- finishing observation could DELETE a newer observation's lease on
-- the same slot, silently opening a concurrency slot that was still in
-- use.  Token is now the OWNERSHIP identity:
--
--   token       per-acquisition 128-bit crypto/rand hex value
--               (storage.NewLeaseToken).  Two acquisitions in the same
--               process always differ.  holder stays as diagnostic
--               provenance only.
--   release     DELETEs the row matching (scope_id, slot, TOKEN) —
--               an old holder's release can never remove a newer
--               holder's lease.
--   renewal     extends expires_at only for the row matching
--               (scope_id, slot, TOKEN) that is still live
--               (expires_at > now) — a stolen or lapsed lease can
--               never be resurrected (storage.ErrLeaseLost).
--
-- Existing rows (holders from before this upgrade) get '' — they
-- expire per the 0019 TTL and are then stealable, exactly like
-- crashed holders; no backfill is needed or possible (their owners are
-- gone by definition).
--
-- Lease semantics summary (authoritative; docs/SCANNING.md):
--   acquire   INSERT (scope_id, slot, token, expires_at = now + TTL),
--             or steal an EXPIRED row (expires_at <= now) atomically.
--   renew     UPDATE expires_at WHERE (scope_id, slot, token) AND
--             expires_at > now; zero rows ⇒ ErrLeaseLost (fatal for
--             the observation: no new connections).
--   release   DELETE WHERE (scope_id, slot, token); double release is
--             a no-op success.
--   crash     TTL (storage.DefaultScanLeaseTTL, 2 min) bounds the
--             abandoned row; no stale lock can accumulate without
--             limit.
--
-- Transaction-safe like every GSEER migration (single implicit
-- transaction; no CONCURRENTLY, no VACUUM).

-- ---------------------------------------------------------------------------
-- [1] Bootstrap refusal guard — the same contract 0016/0018/0019 enforce.
-- ---------------------------------------------------------------------------
DO $gseer_0020_guard$
DECLARE
    v_failures text[] := '{}';
BEGIN
    IF current_setting('server_version_num')::int < 160000 THEN
        v_failures := v_failures || format(
            'PostgreSQL 16+ required (found server_version_num=%s)',
            current_setting('server_version_num'));
    END IF;
    IF to_regclass('public.scan_leases') IS NULL THEN
        v_failures := v_failures || 'public.scan_leases is missing (migration 0019 not applied?)';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gseer_app') THEN
        v_failures := v_failures ||
            'role gseer_app does not exist; run the deployment bootstrap first (docs/DEPLOYMENT.md §3.1: bootstrap → migrate → grants → audit)'::text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gseer_policy_owner') THEN
        v_failures := v_failures ||
            'role gseer_policy_owner does not exist; run the deployment bootstrap first (docs/DEPLOYMENT.md §3.1: bootstrap → migrate → grants → audit)'::text;
    END IF;
    IF array_length(v_failures, 1) > 0 THEN
        RAISE EXCEPTION 'gseer_0020 guard failed: %', array_to_string(v_failures, ' | ')
            USING ERRCODE = 'GSUP3';
    END IF;
END
$gseer_0020_guard$;

-- ---------------------------------------------------------------------------
-- [2] The token column.  Composite PK (scope_id, slot) already gives the
--     row identity; token needs no index of its own (every lease
--     operation addresses exactly one row by its PK).  No new grants:
--     gseer_app's existing row privileges on scan_leases (0019) cover
--     the new column; least-privilege is unchanged.
-- ---------------------------------------------------------------------------
ALTER TABLE scan_leases ADD COLUMN token TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN scan_leases.token IS
    'Per-acquisition lease ownership identity: 128-bit crypto/rand hex (storage.NewLeaseToken). Release and renewal are token-scoped — an old holder can never delete or renew a newer holder''s lease; renewal refuses lapsed/stolen leases (ErrLeaseLost). Final-security-microfix FIX B.';
