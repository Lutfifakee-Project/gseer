-- 0011 down — restore the 0007/0008 window-function view layer and drop
-- the maintained projection tables + R44 indexes.  The re-derived views
-- produce the same winners as the tables did (same ORDER BY and the same
-- 0007/0008 projections), so a downgrade is lossless for search results;
-- only the maintained-table performance shape is lost.

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
SELECT service_id, status, title, server, headers, observed_at FROM (
    SELECT o.service_id AS service_id,
           CAST(json_extract(o.evidence, '$.http.status') AS INTEGER) AS status,
           json_extract(o.evidence, '$.http.title')  AS title,
           json_extract(o.evidence, '$.http.server') AS server,
           CASE WHEN json_type(o.evidence, '$.http.headers') = 'object'
                THEN json_extract(o.evidence, '$.http.headers') END AS headers,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.http') IS NOT NULL
) WHERE rn = 1;

CREATE VIEW latest_tls AS
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn,
       cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns,
       cert_not_before, observed_at FROM (
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
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.tls') IS NOT NULL
) WHERE rn = 1;

CREATE VIEW latest_fingerprints AS
SELECT service_id, technologies, banner, observed_at FROM (
    SELECT o.service_id AS service_id,
           CASE
             WHEN json_type(o.evidence, '$.fingerprint.technologies') = 'array'
             THEN json_extract(o.evidence, '$.fingerprint.technologies')
             ELSE '[]'
           END AS technologies,
           json_extract(o.evidence, '$.ssh.banner') AS banner,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.fingerprint') IS NOT NULL
) WHERE rn = 1;
