-- 0010 down — restore the 0009 view layer (the dns_record column
-- leaves the search surface; raw $.dns evidence is untouched).

DROP VIEW IF EXISTS latest_dns;

-- 0009 — CT log searchable surface (R39 P2): the SQLite twin of shared
-- migration 0025 — the asset-level Certificate Transparency evidence
-- ($.ctlog — the seed-free ctlog connector, R36+) is projected into a
-- latest-per-asset view and appended to search_index.  The CT record
-- stays what it is: a name that appears in a cryptographically logged
-- certificate — NOT a live/DNS-resolved or HTTP-observed hostname; the
-- field group keeps the `ct.` prefix so the distinction stays visible
-- at query time.
--
-- Columns appended to search_index (both UNION branches, in order):
--   ct_log, ct_entry_type, ct_subject_cn, ct_issuer,
--   ct_not_before, ct_not_after, ct_leaf_sha256, ct_cert_timestamp

DROP VIEW IF EXISTS search_index;
DROP VIEW IF EXISTS latest_ctlog;
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
       i2a.prefix AS ip_prefix,
       ct."log" AS ct_log, ct.entry_type AS ct_entry_type,
       ct.subject_cn AS ct_subject_cn, ct.issuer AS ct_issuer,
       ct.not_before AS ct_not_before, ct.not_after AS ct_not_after,
       ct.leaf_sha256 AS ct_leaf_sha256, ct.cert_timestamp AS ct_cert_timestamp
FROM services s
JOIN assets a ON a.id = s.asset_id
LEFT JOIN latest_http h ON h.service_id = s.id
LEFT JOIN latest_tls tls ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
LEFT JOIN latest_ctlog ct ON ct.asset_id = a.id
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
       NULL, NULL, NULL, i2a.prefix,
       ct."log" AS ct_log, ct.entry_type AS ct_entry_type,
       ct.subject_cn AS ct_subject_cn, ct.issuer AS ct_issuer,
       ct.not_before AS ct_not_before, ct.not_after AS ct_not_after,
       ct.leaf_sha256 AS ct_leaf_sha256, ct.cert_timestamp AS ct_cert_timestamp
FROM assets a
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
LEFT JOIN latest_ctlog ct ON ct.asset_id = a.id
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id)
