-- GSEER migration 0019_scan_concurrency_leases.up.sql — the v0.3.2
-- security-microfix enforcement surface (independent-review FIX D/E).
--
-- Scope:
--   scan_leases  — transient per-scope execution leases that make the
--                  scopes.max_concurrency limit a REAL, cross-process
--                  scope-level limit: an observation run must hold one
--                  of the scope's lease slots (1..max_concurrency) for
--                  its entire duration; every process coordinates
--                  through these rows, so separate CLI invocations
--                  cannot exceed the limit.
--   COMMENT ON COLUMN — corrected semantics documentation for the two
--                  execution-limit columns 0018 introduced (historical
--                  migrations are immutable; the wording below is the
--                  authoritative contract).
--
-- Corrected semantics (FIX E — matches the implementation exactly):
--   scopes.max_total_bytes  the ACCUMULATED response-BODY byte ceiling
--                 for ONE observation run: bytes are counted across
--                 every redirect hop of the run (the counter is never
--                 reset on a redirect) and the metric is bytes actually
--                 read from HTTP response bodies (headers are not
--                 counted).  0 = engine default cap.
--   scopes.max_concurrency
--                 the maximum number of SIMULTANEOUS ACTIVE
--                 OBSERVATIONS for this scope, ACROSS ALL PROCESSES,
--                 enforced through scan_leases.  (The 0018 phrasing
--                 "per-run connection concurrency ceiling" described an
--                 intra-run knob the single-threaded observers never
--                 used; the enforceable meaning is the scope-level
--                 simultaneous-observations limit.)
--
-- Lease lifecycle and crash safety:
--   acquire  INSERT (scope_id, slot) with expires_at = now + TTL; on a
--            (scope_id, slot) conflict the row is stolen only when its
--            expires_at has passed (one atomic upsert — see
--            internal/storage/postgres/lease.go).
--   release  the holder DELETEs its own (scope_id, slot, holder) row
--            when the run ends.
--   crash    the abandoned row expires after the TTL (default 2 minutes,
--            storage.DefaultScanLeaseTTL) and is then stealable — stale
--            locks can never accumulate without limit.
--   busy     all slots held by live leases ⇒ ErrScopeBusy ⇒ the observer
--            FAILS CLOSED (no probe is sent).
--   Leases are deliberately MUTABLE transient state (steal + delete) —
--   unlike the append-only scan_audits decision log.
--
-- Transaction-safe like every GSEER migration (single implicit
-- transaction; no CONCURRENTLY, no VACUUM).

-- ---------------------------------------------------------------------------
-- [1] Bootstrap refusal guard — the same contract 0016/0018 enforce: the
--     hardened roles must pre-exist (deployment order: bootstrap →
--     migrate → grants → audit; docs/DEPLOYMENT.md §3.1).
-- ---------------------------------------------------------------------------
DO $gseer_0019_guard$
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
        RAISE EXCEPTION 'gseer_0019 guard failed: %', array_to_string(v_failures, ' | ')
            USING ERRCODE = 'GSUP3';
    END IF;
END
$gseer_0019_guard$;

-- ---------------------------------------------------------------------------
-- [2] scan_leases — the cross-process max_concurrency enforcement.
--     No identity column, no sequence (the composite natural key IS the
--     identity) — consistent with the §5.2 least-privilege rule that
--     grants no sequences.
-- ---------------------------------------------------------------------------
CREATE TABLE scan_leases (
    scope_id    BIGINT      NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    slot        INTEGER     NOT NULL CHECK (slot >= 1),
    holder      TEXT        NOT NULL DEFAULT '',
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope_id, slot)
);

COMMENT ON TABLE scan_leases IS
    'Transient per-scope execution leases (v0.3.2 microfix): one row = one held max_concurrency slot. Mutable by design (steal on expiry, delete on release) — NOT an audit log.';

-- ---------------------------------------------------------------------------
-- [3] Corrected semantics documentation for the 0018 columns (FIX E).
--     Historical migrations are immutable; these comments are the
--     authoritative contract the implementation enforces.
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN scopes.max_total_bytes IS
    'ACCUMULATED response-BODY byte ceiling for one observation run: counted across EVERY redirect hop (never reset on redirect); metric = bytes actually read from HTTP response bodies (headers excluded); 0 = engine default cap. Authoritative wording (supersedes the 0018 phrasing; enforcement landed in v0.3.2).';
COMMENT ON COLUMN scopes.max_concurrency IS
    'Maximum simultaneous ACTIVE OBSERVATIONS for this scope ACROSS ALL PROCESSES, enforced via scan_leases (slots 1..max_concurrency, TTL-bounded, fail-closed when busy). Authoritative wording (supersedes the 0018 per-run phrasing).';

-- ---------------------------------------------------------------------------
-- [4] Additive runtime grant for the lease table (see 0018's grant
--     contract; the pinned §5.2 script itself is NOT modified).
--     Leases are transient: the holder INSERTs, steals (UPDATE) and
--     releases (DELETE) — the full row lifecycle is required, and there
--     is deliberately NO append-only constraint here (unlike
--     scan_audits).  No sequence grants (no identity column exists).
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.scan_leases TO gseer_app;
