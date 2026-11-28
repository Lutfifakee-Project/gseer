-- GSEER migration 0011_perf_latest_tables.up.sql — R44 search performance.
--
-- PROBLEM (measured, R44 evidence): the v0.0.1 latest_http / latest_tls /
-- latest_fingerprints helpers were defined as window-function scans over
-- the WHOLE observations table (ROW_NUMBER() OVER (PARTITION BY
-- service_id ...) with json_valid/json_extract per row).  search_index
-- LEFT JOINs them, so EVERY search — even `ip == "1.2.3.4"` — re-derived
-- the latest-per-service projection over all observations.  At 20k facts
-- a kind-filtered query took ~440 ms and facets ~2.1 s; the cost grows
-- linearly with the observation count, which makes 1M-asset personal
-- indexes unusable.
--
-- FIX (the SPEC-05 §2 design intent, "maintained on write"): the
-- latest-per-service projection becomes maintained TABLES
-- (latest_http_t / latest_tls_t / latest_fingerprints_t) upserted inside
-- the observation-insert transaction by the store layer; the helper
-- VIEWS keep their exact names and column contracts (the 0007/0008 head
-- shapes incl. headers, cert_serial/sans_dns/issuer_org/not_before and
-- the $.ssh.banner projection) and now read the maintained tables, so
-- search_index (and every consumer above it) is unchanged semantically
-- while the whole-table window scan disappears.
--
-- Winner semantics are preserved EXACTLY: newest observed_at wins, ties
-- break on the higher observation id (the same ORDER BY the window used).
-- obs_id is kept in the _t tables so the tie-break can be re-applied on
-- every upsert.  observed_at is stored with the fixed-width tsLayout, so
-- lexicographic string comparison is chronological comparison.
--
-- Backfill: one-time re-derivation from observations with the SAME window
-- (plus obs_id), so an existing database migrates without any rebuild.

CREATE TABLE latest_http_t (
    service_id  INTEGER PRIMARY KEY,
    status      INTEGER,
    title       TEXT,
    server      TEXT,
    headers     TEXT,
    observed_at TEXT NOT NULL,
    obs_id      INTEGER NOT NULL
);

CREATE TABLE latest_tls_t (
    service_id      INTEGER PRIMARY KEY,
    tls_version     TEXT,
    cert_subject_cn TEXT,
    cert_issuer_cn  TEXT,
    cert_issuer_org TEXT,
    cert_expiry     TEXT,
    cert_serial     TEXT,
    cert_sans_dns   TEXT,
    cert_not_before TEXT,
    observed_at     TEXT NOT NULL,
    obs_id          INTEGER NOT NULL
);

CREATE TABLE latest_fingerprints_t (
    service_id   INTEGER PRIMARY KEY,
    technologies TEXT NOT NULL DEFAULT '[]',
    banner       TEXT,
    observed_at  TEXT NOT NULL,
    obs_id       INTEGER NOT NULL
);

-- Backfill latest_http_t (same winner rule + same projections as the
-- 0007 view).
INSERT INTO latest_http_t (service_id, status, title, server, headers, observed_at, obs_id)
SELECT service_id, status, title, server, headers, observed_at, obs_id FROM (
    SELECT o.service_id AS service_id,
           CAST(json_extract(o.evidence, '$.http.status') AS INTEGER) AS status,
           json_extract(o.evidence, '$.http.title')  AS title,
           json_extract(o.evidence, '$.http.server') AS server,
           CASE WHEN json_type(o.evidence, '$.http.headers') = 'object'
                THEN json_extract(o.evidence, '$.http.headers') END AS headers,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.http') IS NOT NULL
) WHERE rn = 1;

-- Backfill latest_tls_t (0008 projections incl. cert_not_before).
INSERT INTO latest_tls_t (service_id, tls_version, cert_subject_cn, cert_issuer_cn, cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns, cert_not_before, observed_at, obs_id)
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn, cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns, cert_not_before, observed_at, obs_id FROM (
    SELECT o.service_id AS service_id,
           json_extract(o.evidence, '$.tls.version')           AS tls_version,
           json_extract(o.evidence, '$.tls.cert_subject_cn')   AS cert_subject_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_cn')    AS cert_issuer_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_org')   AS cert_issuer_org,
           json_extract(o.evidence, '$.tls.cert_expiry')       AS cert_expiry,
           json_extract(o.evidence, '$.tls.cert_serial')       AS cert_serial,
           REPLACE(REPLACE(REPLACE(json_extract(o.evidence, '$.tls.cert_sans_dns'), '[', ''), ']', ''), '"', '')
                                                               AS cert_sans_dns,
           json_extract(o.evidence, '$.tls.cert_not_before')   AS cert_not_before,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.tls') IS NOT NULL
) WHERE rn = 1;

-- Backfill latest_fingerprints_t (0007 projections incl. the $.ssh.banner
-- shape; the row exists only when a $.fingerprint payload is present).
INSERT INTO latest_fingerprints_t (service_id, technologies, banner, observed_at, obs_id)
SELECT service_id, technologies, banner, observed_at, obs_id FROM (
    SELECT o.service_id AS service_id,
           CASE
             WHEN json_type(o.evidence, '$.fingerprint.technologies') = 'array'
             THEN json_extract(o.evidence, '$.fingerprint.technologies')
             ELSE '[]'
           END AS technologies,
           json_extract(o.evidence, '$.ssh.banner') AS banner,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.fingerprint') IS NOT NULL
) WHERE rn = 1;

-- Views keep their names and 0007/0008 column contracts; the scan is gone.
DROP VIEW latest_http;
CREATE VIEW latest_http AS
SELECT service_id, status, title, server, headers, observed_at FROM latest_http_t;

DROP VIEW latest_tls;
CREATE VIEW latest_tls AS
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn,
       cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns,
       cert_not_before, observed_at FROM latest_tls_t;

DROP VIEW latest_fingerprints;
CREATE VIEW latest_fingerprints AS
SELECT service_id, technologies, banner, observed_at FROM latest_fingerprints_t;

-- R44: the value/kind/port/last_seen lookup paths the planner renders for
-- exact-match, IN and sort queries (verified via EXPLAIN QUERY PLAN).
CREATE INDEX ix_assets_value       ON assets (value);
CREATE INDEX ix_assets_kind_value  ON assets (kind, value);
CREATE INDEX ix_services_port      ON services (port);
CREATE INDEX ix_services_last_seen ON services (last_seen);
