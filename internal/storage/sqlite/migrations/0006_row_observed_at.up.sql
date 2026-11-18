-- GSEER migration 0006_row_observed_at.up.sql — the observed_at search
-- field for the personal (SQLite) engine; the dialect mirror of the PG
-- migration 0022 (v0.3.2 query-engine completion).
--
-- observations.observed_at is the REAL evidence time; first_seen /
-- last_seen are import/ingest stamps.  The helper view
-- latest_row_observed_at takes the newest observation per search_index
-- row identity — (asset_id, COALESCE(service_id, 0)) so service rows
-- and asset-only rows share one GROUP BY — and the search_index union
-- view gains an observed_at column in the same position on both
-- branches.  observed_at is stored as the SQ-02 fixed-width UTC micro
-- string, so lexicographic order equals chronological order (the same
-- contract first_seen/last_seen already follow).
--
-- Down: restores the 0005 search_index definition verbatim.

DROP VIEW IF EXISTS latest_row_observed_at;
CREATE VIEW latest_row_observed_at AS
SELECT asset_id,
       COALESCE(service_id, 0) AS svc_key,
       MAX(observed_at)        AS observed_at
FROM observations
GROUP BY asset_id, COALESCE(service_id, 0);

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
       a.sources, a.first_seen, s.last_seen, obs.observed_at, s.stale
FROM services s
JOIN assets a ON a.id = s.asset_id
LEFT JOIN latest_http h ON h.service_id = s.id
LEFT JOIN latest_tls tls ON tls.service_id = s.id
LEFT JOIN latest_fingerprints fp ON fp.service_id = s.id
LEFT JOIN latest_row_observed_at obs ON obs.asset_id = a.id AND obs.svc_key = s.id
UNION ALL
SELECT a.id, 'asset-only', a.id, a.kind, a.value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       NULL, NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, obs.observed_at, 0
FROM assets a
LEFT JOIN latest_row_observed_at obs ON obs.asset_id = a.id AND obs.svc_key = 0
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
