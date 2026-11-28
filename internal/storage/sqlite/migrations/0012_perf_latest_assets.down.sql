-- 0012 down — restore the 0007/0009/0010 window-function view layer for
-- the asset-granular helpers and drop the maintained projection tables.
-- The re-derived views produce the same winners the tables did.

DROP VIEW IF EXISTS latest_ip2asn;
DROP VIEW IF EXISTS latest_ctlog;
DROP VIEW IF EXISTS latest_dns;

DROP TABLE IF EXISTS latest_ip2asn_t;
DROP TABLE IF EXISTS latest_ctlog_t;
DROP TABLE IF EXISTS latest_dns_t;

CREATE VIEW latest_ip2asn AS
SELECT asset_id, prefix, observed_at FROM (
    SELECT o.asset_id AS asset_id,
           json_extract(o.evidence, '$.ip2asn.prefix') AS prefix,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.ip2asn.prefix') IS NOT NULL
) WHERE rn = 1;

CREATE VIEW latest_ctlog AS
SELECT asset_id, "log", entry_type, subject_cn, issuer,
       not_before, not_after, leaf_sha256, cert_timestamp, observed_at FROM (
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
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.ctlog') IS NOT NULL
) WHERE rn = 1;

CREATE VIEW latest_dns AS
SELECT asset_id, dns_record, observed_at FROM (
    SELECT o.asset_id AS asset_id,
           CASE WHEN json_type(o.evidence, '$.dns') = 'object'
                THEN json_extract(o.evidence, '$.dns')
           END AS dns_record,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.asset_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.asset_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.dns') IS NOT NULL
) WHERE rn = 1;
