-- 0006 — evidence quality (R36 P2/P3): the maintained asset-evidence
-- table that makes every search row carry its provenance families, the
-- latest observation timestamp and the coverage class.
--
--   evidence_kinds  — DISTINCT fact-source families as a JSON array:
--                     ct (CT discovery) | dns (DNS observation) |
--                     bgp (BGP routing, RouteViews prefixes) |
--                     asn (IP-to-ASN attribution) | http / tls
--                     (authorized scan observations).  The bgp/asn
--                     split keeps ROUTING evidence and ATTRIBUTION
--                     evidence distinguishable in search results.
--   last_observed   — the max observed_at over the asset's observations
--                     (trigger-maintained; freshness, R33 semantics).
--   coverage_class  — the P3/P4 coverage story, strongest evidence
--                     wins: service-observed (both scanners) >
--                     tls-observed / http-observed (one scanner) >
--                     routing-confirmed (BGP prefix facts or ASN
--                     attribution) > dns-resolved > discovered;
--                     unclassified for assets without recognized
--                     sources.
--
-- Maintained by triggers (the same pattern as the 0002 freshness
-- columns): no scanner or collector writes this table directly.

CREATE TABLE asset_evidence (
    asset_id       INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    evidence_kinds TEXT NOT NULL DEFAULT '[]',
    last_observed  TEXT,
    coverage_class TEXT NOT NULL DEFAULT 'unclassified'
);

CREATE INDEX ix_asset_evidence_class ON asset_evidence (coverage_class);

CREATE TRIGGER trg_asset_evidence_insert
AFTER INSERT ON assets
BEGIN
    INSERT INTO asset_evidence (asset_id, evidence_kinds, last_observed, coverage_class)
    VALUES (NEW.id,
        (SELECT json_group_array(DISTINCT kind)
         FROM (SELECT CASE
           WHEN je.value LIKE 'scan-tls%' THEN 'tls'
           WHEN je.value LIKE 'scan-%'  THEN 'http'
           WHEN je.value LIKE 'bgp-%'   THEN 'bgp'
           WHEN je.value LIKE 'ip2asn%' THEN 'asn'
           WHEN je.value LIKE 'dns-%'   THEN 'dns'
           WHEN je.value LIKE 'ct-%'    THEN 'ct'
         END AS kind
         FROM json_each(NEW.sources) AS je) AS k
         WHERE kind IS NOT NULL),
        NULL,
        COALESCE((SELECT CASE
          WHEN SUM(value LIKE 'scan-%') > 0 THEN
            CASE WHEN SUM(value LIKE 'scan-tls%') > 0 AND SUM(value LIKE 'scan-http%') > 0 THEN 'service-observed'
                 WHEN SUM(value LIKE 'scan-tls%') > 0 THEN 'tls-observed'
                 ELSE 'http-observed' END
          WHEN SUM(value LIKE 'bgp-%' OR value LIKE 'ip2asn%') > 0 THEN 'routing-confirmed'
          WHEN SUM(value LIKE 'dns-%') > 0 THEN 'dns-resolved'
          WHEN SUM(value LIKE 'ct-%') > 0 THEN 'discovered'
          ELSE 'unclassified'
        END
         FROM json_each(NEW.sources) AS je
         HAVING COUNT(*) > 0), 'unclassified'));
END;

CREATE TRIGGER trg_asset_evidence_sources_update
AFTER UPDATE OF sources ON assets
BEGIN
    UPDATE asset_evidence
       SET evidence_kinds = (SELECT json_group_array(DISTINCT kind)
             FROM (SELECT CASE
               WHEN je.value LIKE 'scan-tls%' THEN 'tls'
               WHEN je.value LIKE 'scan-%'  THEN 'http'
               WHEN je.value LIKE 'bgp-%'   THEN 'bgp'
               WHEN je.value LIKE 'ip2asn%' THEN 'asn'
               WHEN je.value LIKE 'dns-%'   THEN 'dns'
               WHEN je.value LIKE 'ct-%'    THEN 'ct'
             END AS kind
             FROM json_each(NEW.sources) AS je) AS k
             WHERE kind IS NOT NULL),
           coverage_class = COALESCE((SELECT CASE
          WHEN SUM(value LIKE 'scan-%') > 0 THEN
            CASE WHEN SUM(value LIKE 'scan-tls%') > 0 AND SUM(value LIKE 'scan-http%') > 0 THEN 'service-observed'
                 WHEN SUM(value LIKE 'scan-tls%') > 0 THEN 'tls-observed'
                 ELSE 'http-observed' END
          WHEN SUM(value LIKE 'bgp-%' OR value LIKE 'ip2asn%') > 0 THEN 'routing-confirmed'
          WHEN SUM(value LIKE 'dns-%') > 0 THEN 'dns-resolved'
          WHEN SUM(value LIKE 'ct-%') > 0 THEN 'discovered'
          ELSE 'unclassified'
        END
             FROM json_each(NEW.sources) AS je
             HAVING COUNT(*) > 0), 'unclassified')
     WHERE asset_id = NEW.id;
END;

CREATE TRIGGER trg_asset_evidence_observation_insert
AFTER INSERT ON observations
BEGIN
    UPDATE asset_evidence
       SET last_observed = max(
             COALESCE((SELECT last_observed FROM asset_evidence WHERE asset_id = NEW.asset_id), NEW.observed_at),
             NEW.observed_at)
     WHERE asset_id = NEW.asset_id;
END;
