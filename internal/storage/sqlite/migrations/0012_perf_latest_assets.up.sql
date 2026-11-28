-- GSEER migration 0012_perf_latest_assets.up.sql — R44 search performance,
-- part 2: the ASSET-granular helper views.
--
-- Same disease as 0011 (service-granular helpers): latest_ip2asn (0007),
-- latest_ctlog (0009) and latest_dns (0010) are ROW_NUMBER() window scans
-- over the WHOLE observations table, joined into search_index on every
-- query.  They become maintained tables (latest_ip2asn_t / latest_ctlog_t
-- / latest_dns_t, upserted inside the observation-insert transaction)
-- behind views with identical names and columns.  Winner semantics
-- preserved exactly: newest observed_at wins, ties break on the higher
-- observation id.  One-time backfill, so an existing database migrates
-- without a rebuild.

CREATE TABLE latest_ip2asn_t (
    asset_id    INTEGER PRIMARY KEY,
    prefix      TEXT,
    observed_at TEXT NOT NULL,
    obs_id      INTEGER NOT NULL
);

CREATE TABLE latest_ctlog_t (
    asset_id       INTEGER PRIMARY KEY,
    "log"          TEXT,
    entry_type     TEXT,
    subject_cn     TEXT,
    issuer         TEXT,
    not_before     TEXT,
    not_after      TEXT,
    leaf_sha256    TEXT,
    cert_timestamp TEXT,
    observed_at    TEXT NOT NULL,
    obs_id         INTEGER NOT NULL
);

CREATE TABLE latest_dns_t (
    asset_id    INTEGER PRIMARY KEY,
    dns_record  TEXT,
    observed_at TEXT NOT NULL,
    obs_id      INTEGER NOT NULL
);

-- Backfill latest_ip2asn_t (0007 projections).
INSERT INTO latest_ip2asn_t (asset_id, prefix, observed_at, obs_id)
SELECT asset_id, prefix, observed_at, obs_id FROM (
    SELECT o.asset_id AS asset_id,
           json_extract(o.evidence, '$.ip2asn.prefix') AS prefix,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.ip2asn.prefix') IS NOT NULL
) WHERE rn = 1;

-- Backfill latest_ctlog_t (0009 projections).
INSERT INTO latest_ctlog_t (asset_id, "log", entry_type, subject_cn, issuer, not_before, not_after, leaf_sha256, cert_timestamp, observed_at, obs_id)
SELECT asset_id, "log", entry_type, subject_cn, issuer, not_before, not_after, leaf_sha256, cert_timestamp, observed_at, obs_id FROM (
    SELECT o.asset_id AS asset_id,
           json_extract(o.evidence, '$.ctlog.log')             AS "log",
           json_extract(o.evidence, '$.ctlog.entry_type')      AS entry_type,
           json_extract(o.evidence, '$.ctlog.subject_cn')      AS subject_cn,
           json_extract(o.evidence, '$.ctlog.issuer')          AS issuer,
           json_extract(o.evidence, '$.ctlog.not_before')      AS not_before,
           json_extract(o.evidence, '$.ctlog.not_after')       AS not_after,
           json_extract(o.evidence, '$.ctlog.leaf_sha256')     AS leaf_sha256,
           json_extract(o.evidence, '$.ctlog.cert_timestamp')  AS cert_timestamp,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.ctlog') IS NOT NULL
) WHERE rn = 1;

-- Backfill latest_dns_t (0010 projections).
INSERT INTO latest_dns_t (asset_id, dns_record, observed_at, obs_id)
SELECT asset_id, dns_record, observed_at, obs_id FROM (
    SELECT o.asset_id AS asset_id,
           CASE WHEN json_type(o.evidence, '$.dns') = 'object'
                THEN json_extract(o.evidence, '$.dns')
           END AS dns_record,
           o.observed_at AS observed_at,
           o.id          AS obs_id,
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.dns') IS NOT NULL
) WHERE rn = 1;

-- Views keep their names and 0007/0009/0010 column contracts.
DROP VIEW latest_ip2asn;
CREATE VIEW latest_ip2asn AS
SELECT asset_id, prefix, observed_at FROM latest_ip2asn_t;

DROP VIEW latest_ctlog;
CREATE VIEW latest_ctlog AS
SELECT asset_id, "log", entry_type, subject_cn, issuer,
       not_before, not_after, leaf_sha256, cert_timestamp, observed_at
FROM latest_ctlog_t;

DROP VIEW latest_dns;
CREATE VIEW latest_dns AS
SELECT asset_id, dns_record, observed_at FROM latest_dns_t;
