-- GSEER migration 0021_cert_projection.down.sql — ordered rollback.
--
-- Restores the 0017 (latest_tls) and 0003 (search_index) view
-- definitions VERBATIM — the exact statements those up files produced —
-- so the schema matches the post-0020 state (latest_http and
-- latest_fingerprints are untouched by 0021 and stay as they are).
--
-- NOTE: rolling back removes cert_serial / cert_sans_dns from the
-- searchable surface; queries naming tls.cert_serial / tls.cert_sans_dns
-- will fail with GQL_E_FIELD until the migration is re-applied.

CREATE OR REPLACE VIEW latest_tls AS
SELECT DISTINCT ON (o.service_id)
       o.service_id,
       o.evidence -> 'tls' ->> 'version'        AS tls_version,
       o.evidence -> 'tls' ->> 'cert_subject_cn' AS cert_subject_cn,
       o.evidence -> 'tls' ->> 'cert_issuer_cn'  AS cert_issuer_cn,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' -> 'cert_expiry') AS cert_expiry,
       o.observed_at
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'tls'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

CREATE OR REPLACE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       tls.tls_version, tls.cert_subject_cn, tls.cert_issuer_cn, tls.cert_expiry,
       fp.technologies,
       a.sources, a.first_seen, s.last_seen, s.stale
FROM services s
JOIN assets a ON a.id = s.asset_id
LEFT JOIN latest_http h ON h.service_id = s.id
LEFT JOIN latest_tls tls ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
UNION ALL
SELECT a.id, 'asset-only', a.id, a.kind, a.value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       NULL, NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, false
FROM assets a
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
