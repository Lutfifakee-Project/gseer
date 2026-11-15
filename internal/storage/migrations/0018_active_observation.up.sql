-- GSEER migration 0018_active_observation.up.sql — the v0.3.2
-- active-observation authorization surface (P2/PAC regime lands).
--
-- Scope (owner-approved v0.3.2 master prompt §8):
--   scopes      — EXTENDED in place (additive ALTER TABLE; the table was
--                 created by 0006 as the deliberately-unused P2 registry).
--                 The P1 passive connectors still never touch it: these
--                 columns serve `gseer scan` only.
--   scan_audits — one row per gateway decision (allow AND deny), so every
--                 authorization answer is auditable after the fact.
--
-- Extended scopes columns (all additive, all defaulted — no rewrite):
--   protocols        explicit protocol permissions.  Empty array = NO
--                    protocol allowed (default-deny).  Allowed values are
--                    enforced in Go ('http', 'tls').
--   ports            explicit port restrictions.  Empty array = NO port
--                    allowed (default-deny).  Values 1–65535.
--   expires_at       NULL = never expires; otherwise an expired scope is
--                    DEAD (deny) — the gateway re-checks on every decision.
--   revoked_at       NULL = active; a revoked scope is DEAD (deny).
--   max_concurrency  per-run connection concurrency ceiling (>=1).
--   max_requests     per-run request/handshake budget (>=1).
--   max_total_bytes  per-run accumulated response-byte ceiling
--                    (0 = engine default cap applies).
--
-- Audit contract: every gateway decision — allow or deny, and the reason
-- for every deny — is INSERTed into scan_audits by the Go gateway
-- (internal/observe).  Authorization failures NEVER trigger a probe; the
-- audit row is the probe's predecessor, not its substitute.
--
-- Grant contract (hardened self-hosted): the Rev 6.7.2 §5.2 runtime
-- grant matrix predates the active-observation surface and pins
-- `public.scopes: NOT granted` for v0.2.x.  This migration — the
-- P2 milestone that ACTIVATES the registry — extends the matrix
-- additively for the two objects it creates/extends, following the
-- 0016 guard pattern (roles must pre-exist; bootstrap precedes migrate):
--     gseer_app: SELECT, INSERT, UPDATE on public.scopes
--                (create/update = operator CLI; revoke = UPDATE revoked_at;
--                 no DELETE path — revoked rows are history, not garbage)
--     gseer_app: SELECT, INSERT on public.scan_audits
--                (append-only audit; no UPDATE/DELETE path)
--     NO sequence grants: identity columns need none and the §5 audit
--     treats any sequence privilege as a least-privilege violation.
-- The fail-closed effective-privilege audit (Rev 6.7.2 §5) is unaffected:
-- it checks role attributes, suppressions-specific ACLs, and object
-- ownership — extra additive grants on the active-observation objects
-- do not widen any pinned restriction.  gseer_app still owns nothing.
--
-- Transaction-safe like every GSEER migration (single implicit
-- transaction; no CONCURRENTLY, no VACUUM).

-- ---------------------------------------------------------------------------
-- [1] Bootstrap refusal guard — the same contract 0016 enforces: the
--     hardened roles must pre-exist (deployment order: bootstrap →
--     migrate → grants → audit; docs/DEPLOYMENT.md §3.1).
-- ---------------------------------------------------------------------------
DO $gseer_0018_guard$
DECLARE
    v_failures text[] := '{}';
BEGIN
    IF current_setting('server_version_num')::int < 160000 THEN
        v_failures := v_failures || format(
            'PostgreSQL 16+ required (found server_version_num=%s)',
            current_setting('server_version_num'));
    END IF;
    IF to_regclass('public.scopes') IS NULL THEN
        v_failures := v_failures || 'public.scopes is missing (migration 0006 not applied?)';
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
        RAISE EXCEPTION 'gseer_0018 guard failed: %', array_to_string(v_failures, ' | ')
            USING ERRCODE = 'GSUP3';
    END IF;
END
$gseer_0018_guard$;

-- ---------------------------------------------------------------------------
-- [2] scopes — extend the deferred P2 registry in place.
-- ---------------------------------------------------------------------------
ALTER TABLE scopes
    ADD COLUMN protocols       TEXT[]     NOT NULL DEFAULT '{}',
    ADD COLUMN ports           INTEGER[]  NOT NULL DEFAULT '{}',
    ADD COLUMN expires_at      TIMESTAMPTZ,
    ADD COLUMN revoked_at      TIMESTAMPTZ,
    ADD COLUMN max_concurrency INTEGER    NOT NULL DEFAULT 1,
    ADD COLUMN max_requests    INTEGER    NOT NULL DEFAULT 1,
    ADD COLUMN max_total_bytes BIGINT     NOT NULL DEFAULT 0;

-- Port-range validity (1–65535, the same rule the services table
-- enforces on its port column) is enforced in the Go storage layer on
-- every write (both engines) — CHECK constraints cannot contain the
-- unnest() subquery this array shape would need, and duplicating the
-- rule as SQL would diverge from the shared validator.

-- ---------------------------------------------------------------------------
-- [3] scan_audits — append-only gateway decision log (allow AND deny).
--     decision/reason live as plain columns for audit queries; `detail`
--     carries the structured context (matched scope, resolved address,
--     redirect hop depth, ...) as JSON.
-- ---------------------------------------------------------------------------
CREATE TABLE scan_audits (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- the operator-facing target and the address the gateway actually
    -- validated (empty when the decision fired before resolution, e.g.
    -- "no scope at all").
    target_host TEXT        NOT NULL DEFAULT '',
    target_ip   TEXT        NOT NULL DEFAULT '',
    port        INTEGER,
    protocol    TEXT        NOT NULL DEFAULT '',
    decision    TEXT        NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason      TEXT        NOT NULL DEFAULT '',
    scope_id    BIGINT      REFERENCES scopes(id) ON DELETE SET NULL,
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_scan_audits_ts ON scan_audits (ts DESC);
CREATE INDEX ix_scan_audits_target ON scan_audits (target_host, ts DESC);

-- ---------------------------------------------------------------------------
-- [4] Additive runtime grants for the active-observation surface (see the
--     grant contract in the header; the pinned §5.2 script itself is NOT
--     modified — historical deployment artifacts are immutable).
-- ---------------------------------------------------------------------------
-- Identity columns need NO sequence grants (PostgreSQL checks the
-- table INSERT privilege for GENERATED ... AS IDENTITY — the same
-- reason the §5.2 matrix grants no sequences), and the fail-closed
-- effective-privilege audit ENFORCES that: any sequence privilege held
-- by gseer_app is a least-privilege violation.  Exactly two table
-- grants, nothing else.
GRANT SELECT, INSERT, UPDATE ON TABLE public.scopes      TO gseer_app;
GRANT SELECT, INSERT         ON TABLE public.scan_audits TO gseer_app;
