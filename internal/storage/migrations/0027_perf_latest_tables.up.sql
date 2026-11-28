-- GSEER migration 0027_perf_latest_tables.up.sql — R44 search performance
-- (the PostgreSQL twin of the personal-mode 0011 migration).
--
-- Same problem, same fix, same contract: latest_http / latest_tls /
-- latest_fingerprints were DISTINCT ON scans over the whole observations
-- table re-run by every search_index query.  They become maintained
-- tables (upserted inside the observation-insert transaction by the
-- store layer) behind views with identical names and columns (the
-- 0023/0024 head shapes incl. http_headers, cert_serial/sans_dns/
-- issuer_org/not_before and the $.ssh.banner projection).  Winner
-- semantics preserved exactly: newest observed_at wins, ties break on
-- the higher observation id.

CREATE TABLE latest_http_t (
    service_id  BIGINT PRIMARY KEY,
    status      INTEGER,
    title       TEXT,
    server      TEXT,
    http_headers JSONB,
    observed_at TIMESTAMPTZ NOT NULL,
    obs_id      BIGINT NOT NULL
);

CREATE TABLE latest_tls_t (
    service_id      BIGINT PRIMARY KEY,
    tls_version     TEXT,
    cert_subject_cn TEXT,
    cert_issuer_cn  TEXT,
    cert_issuer_org TEXT,
    cert_expiry     TIMESTAMPTZ,
    cert_serial     TEXT,
    cert_sans_dns   TEXT,
    cert_not_before TIMESTAMPTZ,
    observed_at     TIMESTAMPTZ NOT NULL,
    obs_id          BIGINT NOT NULL
);

CREATE TABLE latest_fingerprints_t (
    service_id   BIGINT PRIMARY KEY,
    technologies TEXT[] NOT NULL DEFAULT '{}',
    banner       TEXT,
    observed_at  TIMESTAMPTZ NOT NULL,
    obs_id       BIGINT NOT NULL
);

-- One-time backfill with the SAME DISTINCT ON winner rule and the SAME
-- 0023/0024 projections (plus obs_id for future tie-breaks), so an
-- existing database migrates without a rebuild.
INSERT INTO latest_http_t (service_id, status, title, server, http_headers, observed_at, obs_id)
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       (o.evidence -> 'http' ->> 'status')::integer AS status,
       o.evidence -> 'http' ->> 'title'             AS title,
       o.evidence -> 'http' ->> 'server'            AS server,
       CASE WHEN jsonb_typeof(o.evidence -> 'http' -> 'headers') = 'object'
            THEN o.evidence -> 'http' -> 'headers'
       END                                          AS http_headers,
       o.observed_at,
       o.id
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'http'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

INSERT INTO latest_tls_t (service_id, tls_version, cert_subject_cn, cert_issuer_cn, cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns, cert_not_before, observed_at, obs_id)
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       o.evidence -> 'tls' ->> 'version'          AS tls_version,
       o.evidence -> 'tls' ->> 'cert_subject_cn'  AS cert_subject_cn,
       o.evidence -> 'tls' ->> 'cert_issuer_cn'   AS cert_issuer_cn,
       o.evidence -> 'tls' ->> 'cert_issuer_org'  AS cert_issuer_org,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' ->> 'cert_expiry') AS cert_expiry,
       o.evidence -> 'tls' ->> 'cert_serial'      AS cert_serial,
       CASE WHEN jsonb_typeof(o.evidence -> 'tls' -> 'cert_sans_dns') = 'array'
            THEN (SELECT string_agg(x, ',')
                  FROM jsonb_array_elements_text(o.evidence -> 'tls' -> 'cert_sans_dns') AS x)
            ELSE o.evidence -> 'tls' ->> 'cert_sans_dns'
       END                                        AS cert_sans_dns,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' -> 'cert_not_before') AS cert_not_before,
       o.observed_at,
       o.id
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'tls'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

INSERT INTO latest_fingerprints_t (service_id, technologies, banner, observed_at, obs_id)
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       ARRAY(
           SELECT jsonb_array_elements_text(o.evidence -> 'fingerprint' -> 'technologies')
       ) AS technologies,
       o.evidence -> 'ssh' ->> 'banner' AS banner,
       o.observed_at,
       o.id
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'fingerprint'
  AND jsonb_typeof(o.evidence -> 'fingerprint' -> 'technologies') = 'array'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

-- Views keep their names and 0023/0024 column contracts; the scan is gone.
DROP VIEW latest_http;
CREATE VIEW latest_http AS
SELECT service_id, status, title, server, http_headers, observed_at FROM latest_http_t;

DROP VIEW latest_tls;
CREATE VIEW latest_tls AS
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn, cert_issuer_org,
       cert_expiry, observed_at, cert_serial, cert_sans_dns, cert_not_before
FROM latest_tls_t;

DROP VIEW latest_fingerprints;
CREATE VIEW latest_fingerprints AS
SELECT service_id, technologies, banner, observed_at FROM latest_fingerprints_t;

-- R44 index coverage for the value/kind/port/last_seen planner paths
-- (mirrors the personal-mode 0011 indexes; ix_assets_ip GiST and the
-- 0004 scan indexes already exist on this engine).  Transaction-safe
-- like every GSEER migration (no CONCURRENTLY): this file runs inside
-- the migration transaction.
CREATE INDEX ix_assets_value       ON assets (value);
CREATE INDEX ix_assets_kind_value  ON assets (kind, value);
CREATE INDEX ix_services_port      ON services (port);
CREATE INDEX ix_services_last_seen ON services (last_seen);
