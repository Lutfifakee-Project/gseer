-- GSEER personal-mode migration 0003_scan_concurrency_leases.up.sql —
-- the v0.3.2 security-microfix lease surface for personal mode (1:1
-- port of the PostgreSQL 0019 contract, using the personal dialect).
--
-- Scope:
--   scan_leases  — transient per-scope execution leases that make the
--                  scopes.max_concurrency limit a REAL, cross-process
--                  scope-level limit: an observation run must hold one
--                  of the scope's lease slots (1..max_concurrency) for
--                  its entire duration; every process coordinates
--                  through these rows in the shared SQLite file, so
--                  separate CLI invocations cannot exceed the limit.
--
-- Corrected semantics for the 0002 execution-limit columns (FIX E —
-- matches the implementation exactly; 0002 itself is historical and
-- stays untouched):
--   max_total_bytes  the ACCUMULATED response-BODY byte ceiling for ONE
--                    observation run: bytes are counted across every
--                    redirect hop of the run (never reset on a
--                    redirect); metric = bytes actually read from HTTP
--                    response bodies (headers excluded); 0 = engine
--                    default cap.
--   max_concurrency  the maximum number of SIMULTANEOUS ACTIVE
--                    OBSERVATIONS for this scope, ACROSS ALL PROCESSES,
--                    enforced through scan_leases.
--
-- Lease lifecycle and crash safety (identical to the PG engine):
--   acquire  INSERT (scope_id, slot) with expires_at = now + TTL; on a
--            (scope_id, slot) conflict the row is stolen only when its
--            expires_at has passed (one transaction — see
--            internal/storage/sqlite/lease.go).
--   release  the holder DELETEs its own (scope_id, slot, holder) row.
--   crash    the abandoned row expires after the TTL (default 2
--            minutes, storage.DefaultScanLeaseTTL) and is then
--            stealable — stale locks can never accumulate without
--            limit.
--   busy     all slots held by live leases ⇒ storage.ErrScopeBusy ⇒
--            the observer FAILS CLOSED (no probe is sent).
--
-- schema_migrations is owned by the storage layer's migrate runner.

CREATE TABLE scan_leases (
    scope_id    INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    slot        INTEGER NOT NULL CHECK (slot >= 1),
    holder      TEXT    NOT NULL DEFAULT '',
    acquired_at TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    PRIMARY KEY (scope_id, slot)
);
