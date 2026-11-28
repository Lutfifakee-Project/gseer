-- 0028 down — restore the 0024/0025/0026 DISTINCT ON view layer for the
-- asset-granular helpers and drop the maintained projection tables.  The
-- re-derived views produce the same winners the tables did.

DROP VIEW IF EXISTS latest_ip2asn;
DROP VIEW IF EXISTS latest_ctlog;
DROP VIEW IF EXISTS latest_dns;

DROP TABLE IF EXISTS latest_ip2asn_t;
DROP TABLE IF EXISTS latest_ctlog_t;
DROP TABLE IF EXISTS latest_dns_t;

CREATE VIEW latest_ip2asn AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ip2asn' ->> 'prefix' AS prefix,
       o.observed_at
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ip2asn'
  AND (o.evidence -> 'ip2asn' ->> 'prefix') IS NOT NULL
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

CREATE VIEW latest_ctlog AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ctlog' ->> 'log'            AS "log",
       o.evidence -> 'ctlog' ->> 'entry_type'     AS entry_type,
       o.evidence -> 'ctlog' ->> 'subject_cn'     AS subject_cn,
       o.evidence -> 'ctlog' ->> 'issuer'         AS issuer,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_before') AS not_before,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_after')  AS not_after,
       o.evidence -> 'ctlog' ->> 'leaf_sha256'    AS leaf_sha256,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'cert_timestamp') AS cert_timestamp
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ctlog'
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

CREATE VIEW latest_dns AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       CASE WHEN jsonb_typeof(o.evidence -> 'dns') = 'object'
            THEN o.evidence -> 'dns'
       END AS dns_record,
       o.observed_at
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'dns'
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;
