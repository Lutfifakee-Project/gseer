-- GSEER migration 0028_perf_latest_assets.up.sql — R44 search performance,
-- part 2 (the PostgreSQL twin of the personal-mode 0012 migration).
--
-- latest_ip2asn / latest_ctlog / latest_dns are DISTINCT ON scans over
-- the whole observations table joined into search_index on every query.
-- They become maintained tables behind views with identical names and
-- columns (0024/0025/0026 head shapes).  Winner semantics preserved
-- exactly: newest observed_at wins, ties break on the higher observation
-- id.  One-time backfill with the same projections.

CREATE TABLE latest_ip2asn_t (
    asset_id    BIGINT PRIMARY KEY,
    prefix      TEXT,
    observed_at TIMESTAMPTZ NOT NULL,
    obs_id      BIGINT NOT NULL
);

CREATE TABLE latest_ctlog_t (
    asset_id       BIGINT PRIMARY KEY,
    "log"          TEXT,
    entry_type     TEXT,
    subject_cn     TEXT,
    issuer         TEXT,
    not_before     TIMESTAMPTZ,
    not_after      TIMESTAMPTZ,
    leaf_sha256    TEXT,
    cert_timestamp TIMESTAMPTZ,
    observed_at    TIMESTAMPTZ NOT NULL,
    obs_id         BIGINT NOT NULL
);

CREATE TABLE latest_dns_t (
    asset_id    BIGINT PRIMARY KEY,
    dns_record  JSONB,
    observed_at TIMESTAMPTZ NOT NULL,
    obs_id      BIGINT NOT NULL
);

INSERT INTO latest_ip2asn_t (asset_id, prefix, observed_at, obs_id)
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ip2asn' ->> 'prefix' AS prefix,
       o.observed_at,
       o.id
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ip2asn'
  AND (o.evidence -> 'ip2asn' ->> 'prefix') IS NOT NULL
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

INSERT INTO latest_ctlog_t (asset_id, "log", entry_type, subject_cn, issuer, not_before, not_after, leaf_sha256, cert_timestamp, observed_at, obs_id)
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ctlog' ->> 'log'            AS "log",
       o.evidence -> 'ctlog' ->> 'entry_type'     AS entry_type,
       o.evidence -> 'ctlog' ->> 'subject_cn'     AS subject_cn,
       o.evidence -> 'ctlog' ->> 'issuer'         AS issuer,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_before') AS not_before,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_after')  AS not_after,
       o.evidence -> 'ctlog' ->> 'leaf_sha256'    AS leaf_sha256,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'cert_timestamp') AS cert_timestamp,
       o.observed_at,
       o.id
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ctlog'
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

INSERT INTO latest_dns_t (asset_id, dns_record, observed_at, obs_id)
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       CASE WHEN jsonb_typeof(o.evidence -> 'dns') = 'object'
            THEN o.evidence -> 'dns'
       END AS dns_record,
       o.observed_at,
       o.id
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'dns'
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

-- Views keep their names and 0024/0025/0026 column contracts.
DROP VIEW latest_ip2asn;
CREATE VIEW latest_ip2asn AS
SELECT asset_id, prefix, observed_at FROM latest_ip2asn_t;

DROP VIEW latest_ctlog;
CREATE VIEW latest_ctlog AS
SELECT asset_id, "log", entry_type, subject_cn, issuer,
       not_before, not_after, leaf_sha256, cert_timestamp
FROM latest_ctlog_t;

DROP VIEW latest_dns;
CREATE VIEW latest_dns AS
SELECT asset_id, dns_record, observed_at FROM latest_dns_t;
