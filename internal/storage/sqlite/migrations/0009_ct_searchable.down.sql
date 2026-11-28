-- 0009 down — restore the 0008 view layer (the CT columns leave the
-- search surface; raw $.ctlog evidence is untouched).

DROP VIEW IF EXISTS search_index;
DROP VIEW IF EXISTS latest_ctlog;
CREATE VIEW latest_tls AS
SELECT service_id, tls_version, cert_subject_cn, cert_issuer_cn,
       cert_issuer_org, cert_expiry, cert_serial, cert_sans_dns, cert_not_before, observed_at FROM (
    SELECT o.service_id AS service_id,
           json_extract(o.evidence, '$.tls.version')           AS tls_version,
           json_extract(o.evidence, '$.tls.cert_subject_cn')   AS cert_subject_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_cn')    AS cert_issuer_cn,
           json_extract(o.evidence, '$.tls.cert_issuer_org')   AS cert_issuer_org,
           json_extract(o.evidence, '$.tls.cert_expiry')       AS cert_expiry,
           json_extract(o.evidence, '$.tls.cert_not_before')   AS cert_not_before,
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
CREATE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       tls.tls_version, tls.cert_subject_cn, tls.cert_issuer_cn, tls.cert_expiry,
       tls.cert_serial, tls.cert_sans_dns, tls.cert_not_before,
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
       NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, 0,
       COALESCE(ev.evidence_kinds, '[]'),
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified'),
       NULL, NULL, NULL, i2a.prefix
FROM assets a
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id)
