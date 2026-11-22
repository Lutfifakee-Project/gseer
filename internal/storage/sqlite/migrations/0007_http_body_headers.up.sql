-- GSEER migration 0007_http_body_headers.up.sql — the HTTP body/header
-- search fields for the personal (SQLite) engine.
--
-- The active HTTP observer (internal/observe) records the response body
-- (capped by the observer's byte budget) and a bounded allow-list of
-- interesting response headers in the observation evidence
-- ($.http.body / $.http.headers).  The latest_http helper view extracts
-- both, and the search_index union view gains http_body / http_header
-- columns in the same position on both branches — the planner targets
-- for the GQL `body` / `header` fields (title/server fingerprinting
-- alone cannot see CMS markers like wp-content or X-Pingback).
--
-- Down: restores the 0006 latest_http and search_index definitions
-- verbatim.

DROP VIEW IF EXISTS search_index;
DROP VIEW IF EXISTS latest_http;
CREATE VIEW latest_http AS
SELECT service_id, status, title, server, body, headers, observed_at FROM (
    SELECT o.service_id AS service_id,
           CAST(json_extract(o.evidence, '$.http.status') AS INTEGER) AS status,
           json_extract(o.evidence, '$.http.title')  AS title,
           json_extract(o.evidence, '$.http.server') AS server,
           json_extract(o.evidence, '$.http.body')    AS body,
           json_extract(o.evidence, '$.http.headers') AS headers,
           o.observed_at AS observed_at,
           ROW_NUMBER() OVER (PARTITION BY o.service_id
                              ORDER BY o.observed_at DESC, o.id DESC) AS rn
    FROM observations o
    WHERE o.service_id IS NOT NULL
      AND json_valid(o.evidence)
      AND json_extract(o.evidence, '$.http') IS NOT NULL
) WHERE rn = 1;

CREATE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       h.body AS http_body, h.headers AS http_header,
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
       NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, obs.observed_at, 0
FROM assets a
LEFT JOIN latest_row_observed_at obs ON obs.asset_id = a.id AND obs.svc_key = 0
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
