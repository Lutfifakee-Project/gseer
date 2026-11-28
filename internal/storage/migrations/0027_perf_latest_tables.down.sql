-- 0027 down — restore the 0023/0024 DISTINCT ON view layer and drop the
-- maintained projection tables + R44 indexes.  The re-derived views
-- produce the same winners the tables held (same ORDER BY and the same
-- projections), so a downgrade is lossless for search results; only the
-- maintained-table performance shape is lost.

DROP INDEX IF EXISTS ix_services_last_seen;
DROP INDEX IF EXISTS ix_services_port;
DROP INDEX IF EXISTS ix_assets_kind_value;
DROP INDEX IF EXISTS ix_assets_value;

DROP VIEW IF EXISTS latest_http;
DROP VIEW IF EXISTS latest_tls;
DROP VIEW IF EXISTS latest_fingerprints;

DROP TABLE IF EXISTS latest_http_t;
DROP TABLE IF EXISTS latest_tls_t;
DROP TABLE IF EXISTS latest_fingerprints_t;

CREATE VIEW latest_http AS
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       (o.evidence -> 'http' ->> 'status')::integer AS status,
       o.evidence -> 'http' ->> 'title'             AS title,
       o.evidence -> 'http' ->> 'server'            AS server,
       CASE WHEN jsonb_typeof(o.evidence -> 'http' -> 'headers') = 'object'
            THEN o.evidence -> 'http' -> 'headers'
       END                                          AS http_headers,
       o.observed_at
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'http'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

CREATE VIEW latest_tls AS
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       o.evidence -> 'tls' ->> 'version'          AS tls_version,
       o.evidence -> 'tls' ->> 'cert_subject_cn'  AS cert_subject_cn,
       o.evidence -> 'tls' ->> 'cert_issuer_cn'   AS cert_issuer_cn,
       o.evidence -> 'tls' ->> 'cert_issuer_org'  AS cert_issuer_org,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' ->> 'cert_expiry') AS cert_expiry,
       o.observed_at,
       o.evidence -> 'tls' ->> 'cert_serial'      AS cert_serial,
       CASE WHEN jsonb_typeof(o.evidence -> 'tls' -> 'cert_sans_dns') = 'array'
            THEN (SELECT string_agg(x, ',')
                  FROM jsonb_array_elements_text(o.evidence -> 'tls' -> 'cert_sans_dns') AS x)
            ELSE o.evidence -> 'tls' ->> 'cert_sans_dns'
       END                                        AS cert_sans_dns,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' -> 'cert_not_before') AS cert_not_before
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'tls'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

CREATE VIEW latest_fingerprints AS
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       ARRAY(
           SELECT jsonb_array_elements_text(o.evidence -> 'fingerprint' -> 'technologies')
       ) AS technologies,
       o.evidence -> 'ssh' ->> 'banner' AS banner,
       o.observed_at
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'fingerprint'
  AND jsonb_typeof(o.evidence -> 'fingerprint' -> 'technologies') = 'array'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;
