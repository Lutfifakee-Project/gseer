-- GSEER personal-mode migration 0002_active_observation.up.sql — the
-- v0.3.2 active-observation surface for personal mode (1:1 port of the
-- PostgreSQL 0018 contract, using the personal dialect).
--
-- Scope:
--   scopes      — the full v0.3.2 scope registry (personal mode had NO
--                 scopes table before this migration — the 0006 PG-only
--                 table is now at parity, with every v0.3.2 column).
--   scan_audits — the append-only gateway decision log (allow AND deny).
--
-- Dialect notes (documented in docs/PERSONAL.md, same as 0001):
--   - TIMESTAMP columns are TEXT holding fixed-width UTC microsecond
--     ISO strings ("2006-01-02T15:04:05.000000Z", SQ-02);
--   - the protocols / ports lists are CSV TEXT columns ('http,tls',
--     '80,443'); empty string = NO protocol / NO port allowed
--     (default-deny, the same semantics as the PG empty arrays);
--   - expires_at / revoked_at are NULL until set; expired or revoked
--     scopes are DEAD (deny);
--   - port-range and protocol-value validity are enforced in the Go
--     storage layer on every write (shared with the PG engine);
--   - scan_audits is append-only at the application level (no UPDATE/
--     DELETE path exists in the storage API).
--
-- schema_migrations is owned by the storage layer's migrate runner.

CREATE TABLE scopes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL CHECK (kind IN ('domain', 'domain_suffix', 'cidr', 'ip')),
    value           TEXT    NOT NULL,
    mode            TEXT    NOT NULL DEFAULT 'allow' CHECK (mode IN ('allow', 'deny')),
    note            TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL,
    protocols       TEXT    NOT NULL DEFAULT '',
    ports           TEXT    NOT NULL DEFAULT '',
    expires_at      TEXT,
    revoked_at      TEXT,
    max_concurrency INTEGER NOT NULL DEFAULT 1,
    max_requests    INTEGER NOT NULL DEFAULT 1,
    max_total_bytes INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT scopes_kind_value_unique UNIQUE (kind, value)
);

CREATE TABLE scan_audits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    target_host TEXT    NOT NULL DEFAULT '',
    target_ip   TEXT    NOT NULL DEFAULT '',
    port        INTEGER,
    protocol    TEXT    NOT NULL DEFAULT '',
    decision    TEXT    NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason      TEXT    NOT NULL DEFAULT '',
    scope_id    INTEGER REFERENCES scopes(id) ON DELETE SET NULL,
    detail      TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX ix_scan_audits_ts ON scan_audits (ts DESC);
CREATE INDEX ix_scan_audits_target ON scan_audits (target_host, ts DESC);
