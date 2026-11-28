-- 0022 — evidence quality (R36 P2/P3): the PostgreSQL parity of the
-- sqlite 0006 maintained asset-evidence table.  Same families, same
-- coverage classes, same trigger-maintained semantics.
--
--   evidence_kinds  — DISTINCT fact-source families (jsonb): ct | dns |
--                     bgp (RouteViews routing) | asn (IP-to-ASN
--                     attribution) | http | tls
--   last_observed   — max observed_at over the asset's observations
--   coverage_class  — strongest evidence wins: service-observed (both
--                     scanners) > tls-observed / http-observed (one
--                     scanner) > routing-confirmed > dns-resolved >
--                     discovered > unclassified

CREATE TABLE asset_evidence (
    asset_id       BIGINT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    evidence_kinds JSONB   NOT NULL DEFAULT '[]'::jsonb,
    last_observed  TIMESTAMPTZ,
    coverage_class TEXT    NOT NULL DEFAULT 'unclassified'
);

CREATE INDEX ix_asset_evidence_class ON asset_evidence (coverage_class);

-- gseer_evidence_kinds maps the asset's fact-source family strings to
-- the DISTINCT evidence-kind list.
CREATE OR REPLACE FUNCTION public.gseer_evidence_kinds(sources JSONB)
RETURNS JSONB
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(jsonb_agg(DISTINCT kind), '[]'::jsonb)
    FROM (
        SELECT CASE
            WHEN u.s LIKE 'scan-tls%' THEN 'tls'
            WHEN u.s LIKE 'scan-%'  THEN 'http'
            WHEN u.s LIKE 'bgp-%'   THEN 'bgp'
            WHEN u.s LIKE 'ip2asn%' THEN 'asn'
            WHEN u.s LIKE 'dns-%'   THEN 'dns'
            WHEN u.s LIKE 'ct-%'    THEN 'ct'
        END AS kind
        FROM jsonb_array_elements_text(sources) AS u(s)
    ) k
    WHERE kind IS NOT NULL
$$;

-- gseer_evidence_class derives the coverage class from the fact-source
-- families (the strongest-evidence-wins CASE).
CREATE OR REPLACE FUNCTION public.gseer_evidence_class(sources JSONB)
RETURNS TEXT
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(CASE
            WHEN bool_or(u.s LIKE 'scan-%') THEN
              CASE WHEN bool_or(u.s LIKE 'scan-tls%') AND bool_or(u.s LIKE 'scan-http%') THEN 'service-observed'
                   WHEN bool_or(u.s LIKE 'scan-tls%') THEN 'tls-observed'
                   ELSE 'http-observed' END
            WHEN bool_or(u.s LIKE 'bgp-%' OR u.s LIKE 'ip2asn%') THEN 'routing-confirmed'
            WHEN bool_or(u.s LIKE 'dns-%') THEN 'dns-resolved'
            WHEN bool_or(u.s LIKE 'ct-%') THEN 'discovered'
        END, 'unclassified')
    FROM jsonb_array_elements_text(sources) AS u(s)
$$;

CREATE OR REPLACE FUNCTION public.gseer_asset_evidence_fill()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_evidence (asset_id, evidence_kinds, last_observed, coverage_class)
    VALUES (NEW.id,
            public.gseer_evidence_kinds(NEW.sources),
            NULL,
            public.gseer_evidence_class(NEW.sources))
    ON CONFLICT (asset_id) DO UPDATE
        SET evidence_kinds = public.gseer_evidence_kinds(NEW.sources),
            coverage_class = public.gseer_evidence_class(NEW.sources);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.gseer_asset_evidence_refresh()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE asset_evidence
       SET evidence_kinds = public.gseer_evidence_kinds(NEW.sources),
           coverage_class = public.gseer_evidence_class(NEW.sources)
     WHERE asset_id = NEW.id;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.gseer_asset_evidence_touch()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE asset_evidence
       SET last_observed = greatest(
             COALESCE((SELECT last_observed FROM asset_evidence WHERE asset_id = NEW.asset_id), NEW.observed_at),
             NEW.observed_at)
     WHERE asset_id = NEW.asset_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_asset_evidence_assets_insert
AFTER INSERT ON assets
FOR EACH ROW EXECUTE FUNCTION public.gseer_asset_evidence_fill();

CREATE TRIGGER trg_asset_evidence_assets_update
AFTER UPDATE OF sources ON assets
FOR EACH ROW EXECUTE FUNCTION public.gseer_asset_evidence_refresh();

CREATE TRIGGER trg_asset_evidence_observations_insert
AFTER INSERT ON observations
FOR EACH ROW EXECUTE FUNCTION public.gseer_asset_evidence_touch();
