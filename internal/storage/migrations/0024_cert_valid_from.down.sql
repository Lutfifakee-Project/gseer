-- 0024 down — restore the 0023 view layer (cert_not_before leaves the
-- search surface; raw evidence is untouched).

-- GSEER migration 0023_search_fields.up.sql — R37 search-field
-- expansion (the PostgreSQL twin of sqlite 0007): recreate the helper
-- views with the richer evidence projections and rebuild the
-- search_index union with four appended columns:
--
--   http_headers     jsonb — the latest HTTP observation's captured
--                    headers object; queried per-name through the
--                    DYNAMIC field `http.header.<name>` (the planner
--                    lowers it to http_headers ->> '<name>').
--   cert_issuer_org  TEXT  — issuing organization of the latest TLS
--                    certificate ($.tls.cert_issuer_org, captured
--                    since R36 P2).
--   banner           TEXT  — service banner evidence from the latest
--                    fingerprint observation ($.ssh.banner shape).
--   ip_prefix        TEXT  — the asset's latest IP-to-ASN attribution
--                    prefix ($.ip2asn.prefix) — the `prefix` field.
--
-- The 0006/0021 view semantics are preserved verbatim (DISTINCT ON
-- latest-per-service, jsonb guards, safe timestamptz casts); only the
-- extra projections are added, and search_index keeps the 0022 column
-- order with the four new columns appended at the end.

CREATE OR REPLACE VIEW latest_http AS
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

CREATE OR REPLACE VIEW latest_tls AS
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
       END                                        AS cert_sans_dns
FROM observations o
WHERE o.service_id IS NOT NULL
  AND o.evidence ? 'tls'
ORDER BY o.service_id, o.observed_at DESC, o.id DESC;

CREATE OR REPLACE VIEW latest_fingerprints AS
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

-- latest_ip2asn — R37: latest-per-asset IP-to-ASN attribution prefix
-- (the `prefix` field's backing data; asset-granular like the
-- asset_evidence table).
CREATE OR REPLACE VIEW latest_ip2asn AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ip2asn' ->> 'prefix' AS prefix,
       o.observed_at
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ip2asn'
  AND (o.evidence -> 'ip2asn' ->> 'prefix') IS NOT NULL
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

CREATE OR REPLACE VIEW search_index AS
SELECT s.id AS row_id, 'service' AS row_kind,
       a.id AS asset_id, a.kind AS asset_kind, a.value AS asset_value,
       a.ip, a.domain, a.hostname, a.asn, a.asn_org,
       a.geo_country, a.geo_region, a.geo_city,
       s.port, s.transport, s.protocol, s.name, s.product, s.version,
       h.status AS http_status, h.title AS http_title, h.server AS http_server,
       tls.tls_version, tls.cert_subject_cn, tls.cert_issuer_cn, tls.cert_expiry,
       fp.technologies,
       a.sources, a.first_seen, s.last_seen, s.stale,
       tls.cert_serial, tls.cert_sans_dns,
       COALESCE(ev.evidence_kinds, '[]'::jsonb) AS evidence_kinds,
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified') AS coverage_class,
       h.http_headers,
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
       NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, false,
       NULL, NULL,
       COALESCE(ev.evidence_kinds, '[]'::jsonb),
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified'),
       NULL::jsonb, NULL, NULL, i2a.prefix
FROM assets a
LEFT JOIN asset_evidence ev ON ev.asset_id = a.id
LEFT JOIN latest_ip2asn i2a ON i2a.asset_id = a.id
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
