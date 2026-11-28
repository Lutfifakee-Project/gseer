-- 0010 — DNS record search surface (R39 P3/P4): the SQLite twin of
-- shared migration 0026 — the asset-level DNS evidence ($.dns) is
-- projected as the LATEST dns object per asset and appended to
-- search_index as dns_record (TEXT JSON).  The planner lowers the
-- dynamic field `dns.<key>` (dns.type, dns.query, dns.value, dns.pref)
-- to a json_extract over this object — the same design as
-- http_headers / http.header.<name> (sqlite 0007).
--
-- Honest scope: one latest dns object per asset (the newest answer);
-- the full per-record history stays in observations.  Zone-apex seeds
-- typically carry NO CNAME (apexes are not aliases) — an empty CNAME
-- result is the registry truth, not a search bug.

DROP VIEW IF EXISTS search_index;
DROP VIEW IF EXISTS latest_dns;
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
       ct.leaf_sha256 AS ct_leaf_sha256, ct.cert_timestamp AS ct_cert_timestamp,
       dns.dns_record AS dns_record
FROM services s
JOIN assets a ON a.id = s.asset_id
LEFT JOIN latest_http h ON h.service_id = s.id
LEFT JOIN latest_tls tls ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
LEFT JOIN latest_ctlog ct ON ct.asset_id = a.id
LEFT JOIN latest_dns dns ON dns.asset_id = a.id
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
       ct.leaf_sha256 AS ct_leaf_sha256, ct.cert_timestamp AS ct_cert_timestamp,
       dns.dns_record AS dns_record
FROM assets a
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
LEFT JOIN latest_ctlog ct ON ct.asset_id = a.id
LEFT JOIN latest_dns dns ON dns.asset_id = a.id
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id)
