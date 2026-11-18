-- GSEER migration 0022_row_observed_at.up.sql — the observed_at search
-- field (v0.3.2 query-engine completion).
--
-- The observations table is the canonical provenance surface and keeps
-- the REAL evidence time (observed_at), but the search_index rows only
-- exposed first_seen / last_seen — both import/ingest stamps.  After a
-- `dataset update`, last_seen moves to the import wall clock while the
-- evidence itself may be days old, so freshness filters
-- (after/before/last_seen) did not answer "how old is the evidence?"
-- and the field registry had no observed_at surface at all.
--
-- This migration adds the helper view latest_row_observed_at (the
-- newest observation's observed_at per search_index row identity —
-- (asset_id, service_id) for service rows, (asset_id) for asset-only
-- rows, with COALESCE(service_id, 0) so the two identities share one
-- GROUP BY) and extends the search_index union view with an
-- observed_at column in the same position on both branches:
--
--   observed_at  TIMESTAMPTZ — the row's newest evidence time
--                (searchable: ==/!=/</<=/>/>=; sortable)
--
-- last_seen keeps its existing semantics (bumped by every ingest or
-- import); the two are now honestly distinguishable surfaces.  Down:
-- restores the 0021 search_index definition verbatim and drops the
-- helper view.

CREATE OR REPLACE VIEW latest_row_observed_at AS
SELECT asset_id,
       COALESCE(service_id, 0) AS svc_key,
       MAX(observed_at)        AS observed_at
FROM observations
GROUP BY asset_id, COALESCE(service_id, 0);

-- CREATE OR REPLACE VIEW cannot rename or reorder columns (the
-- observed_at column changes both vs the 0021 layout), so the view
-- is dropped and recreated (no other view depends on it).
DROP VIEW IF EXISTS search_index;
CREATE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       tls.tls_version, tls.cert_subject_cn, tls.cert_issuer_cn, tls.cert_expiry,
       fp.technologies,
       a.sources, a.first_seen, s.last_seen, obs.observed_at, s.stale,
       tls.cert_serial, tls.cert_sans_dns
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
       NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, obs.observed_at, false,
       NULL, NULL
FROM assets a
LEFT JOIN latest_row_observed_at obs ON obs.asset_id = a.id AND obs.svc_key = 0
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
