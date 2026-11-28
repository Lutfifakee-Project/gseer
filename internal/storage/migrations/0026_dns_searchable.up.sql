-- 0026 — DNS record search surface (R39 P3/P4): the asset-level DNS
-- evidence ($.dns — the dns connector's A/AAAA/CNAME/MX/NS/TXT answers)
-- is projected as the LATEST dns object per asset and appended to
-- search_index as dns_record jsonb.  The planner lowers the dynamic
-- field `dns.<key>` (dns.type, dns.query, dns.value, dns.pref) to a
-- key extraction over this object — the same design as http_headers /
-- http.header.<name> (0023).
--
-- Honest scope: one latest dns object per asset (the newest answer);
-- the full per-record history stays in observations.  Zone-apex seeds
-- typically carry NO CNAME (apexes are not aliases) — an empty CNAME
-- result is the registry truth, not a search bug.

CREATE OR REPLACE VIEW latest_dns AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       CASE WHEN jsonb_typeof(o.evidence -> 'dns') = 'object'
            THEN o.evidence -> 'dns'
       END AS dns_record,
       o.observed_at
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'dns'
ORDER BY o.asset_id, o.observed_at DESC, o.id DESC;

-- The 0025 view semantics are preserved verbatim; only the extra
-- projection and the latest_dns join are added, and search_index keeps
-- the 0022/0023/0024/0025 column order with the new column appended
-- at the end.

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
       END                                        AS cert_sans_dns,
       public.gseer_safe_timestamptz(o.evidence -> 'tls' -> 'cert_not_before') AS cert_not_before
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

CREATE OR REPLACE VIEW latest_ctlog AS
SELECT DISTINCT ON (o.asset_id)
       o.asset_id,
       o.evidence -> 'ctlog' ->> 'log'            AS "log",
       o.evidence -> 'ctlog' ->> 'entry_type'     AS entry_type,
       o.evidence -> 'ctlog' ->> 'subject_cn'     AS subject_cn,
       o.evidence -> 'ctlog' ->> 'issuer'         AS issuer,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_before') AS not_before,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'not_after')  AS not_after,
       o.evidence -> 'ctlog' ->> 'leaf_sha256'    AS leaf_sha256,
       public.gseer_safe_timestamptz(o.evidence -> 'ctlog' -> 'cert_timestamp') AS cert_timestamp
FROM observations o
WHERE o.asset_id IS NOT NULL
  AND o.evidence ? 'ctlog'
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
       tls.cert_serial, tls.cert_sans_dns, tls.cert_not_before,
       COALESCE(ev.evidence_kinds, '[]'::jsonb) AS evidence_kinds,
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified') AS coverage_class,
       h.http_headers,
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
       NULL, NULL, NULL, NULL, NULL, NULL,
       a.sources, a.first_seen, a.last_seen, false,
       NULL, NULL,
       COALESCE(ev.evidence_kinds, '[]'::jsonb),
       ev.last_observed,
       COALESCE(ev.coverage_class, 'unclassified'),
       NULL::jsonb, NULL, NULL, i2a.prefix,
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
WHERE NOT EXISTS (SELECT 1 FROM services s WHERE s.asset_id = a.id);
