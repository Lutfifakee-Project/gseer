-- GSEER migration 0007_search_fields.up.sql — R37 search-field
-- expansion: make the richer observation evidence searchable.
--
-- WHAT'S NEW (R37 mandate "searchable intelligence"):
--   http_headers      — the LATEST HTTP observation's captured headers
--                       object, verbatim JSON (whitelist-shaped, hop
--                       last wins).  Queried per-name through the
--                       DYNAMIC field `http.header.<name>` (planner
--                       lowers to json_extract over this column);
--                       the column itself is never a projection
--                       default.
--   cert_issuer_org   — the issuing organization of the latest TLS
--                       certificate (scan evidence $.tls.cert_issuer_org,
--                       captured since R36 P2).
--   banner            — service banner evidence from the latest
--                       fingerprint observation ($.ssh.banner shape).
--   ip_prefix         — the asset's latest IP-to-ASN attribution prefix
--                       ($.ip2asn.prefix) — the `prefix` field.
--
-- The helper views are recreated (views cannot be ALTERed); their
-- definitions keep the R33/R36 contracts: latest-per-service /
-- latest-per-asset ROW_NUMBER ordering, json_valid guards, and the
-- 0005 cert projection columns.  search_index keeps the exact 0006
-- column order and APPENDS the four new columns at the end — the
-- planner's projection is explicit, so existing consumers are
-- unaffected.

DROP VIEW IF EXISTS latest_http;
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

DROP VIEW IF EXISTS latest_tls;
CREATE VIEW latest_tls AS
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn,
       cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns, observed_at FROM (
    SELECT o.service_id AS service_id,
           json_extract(o.evidence, '$.tls.version')           AS tls_version,
           json_extract(o.evidence, '$.tls.cert_subject_cn')   AS cert_subject_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_cn')    AS cert_issuer_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_org')   AS cert_issuer_org,
           json_extract(o.evidence, '$.tls.cert_expiry')       AS cert_expiry,
           json_extract(o.evidence, '$.tls.cert_serial')       AS cert_serial,
           REPLACE(REPLACE(REPLACE(json_extract(o.evidence, '$.tls.cert_sans_dns'), '[', ''), ']', ''), '"', '')
                                                               AS cert_sans_dns,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.tls') IS NOT NULL
) WHERE rn = 1;

DROP VIEW IF EXISTS latest_fingerprints;
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

-- latest_ip2asn — R37: latest-per-asset IP-to-ASN attribution prefix,
-- the `prefix` search field's backing data (asset-granular, like the
-- asset_evidence table: one row per asset, newest observation wins).
DROP VIEW IF EXISTS latest_ip2asn;
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

DROP VIEW IF EXISTS search_index;
CREATE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       tls.tls_version, tls.cert_subject_cn, tls.cert_issuer_cn, tls.cert_expiry,
       tls.cert_serial, tls.cert_sans_dns,
       fp.technologies,
       a.sources, a.first_seen, s.last_seen, s.stale,
       ev.evidence_kinds, ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified') AS coverage_class,
       h.headers AS http_headers,
       tls.cert_issuer_org,
       fp.banner,
       i2a.prefix AS ip_prefix
FROM services s
JOIN assets a ON a.id = s.asset_id
LEFT JOIN latest_http h ON h.service_id = s.id
LEFT JOIN latest_tls tls ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
UNION ALL
SELECT a.id, 'asset-only', a.id, a.kind, a.value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       NULL, NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, 0,
       COALESCE(ev.evidence_kinds, '[]'),
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified'),
       NULL, NULL, NULL, i2a.prefix
FROM assets a
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
