-- 0022 down — drop the maintained evidence surface (parity of the
-- sqlite 0006 down).

DROP TRIGGER IF EXISTS trg_asset_evidence_observations_insert ON observations;
DROP TRIGGER IF EXISTS trg_asset_evidence_assets_update ON assets;
DROP TRIGGER IF EXISTS trg_asset_evidence_assets_insert ON assets;
DROP FUNCTION IF EXISTS public.gseer_asset_evidence_touch();
DROP FUNCTION IF EXISTS public.gseer_asset_evidence_refresh();
DROP FUNCTION IF EXISTS public.gseer_asset_evidence_fill();
DROP FUNCTION IF EXISTS public.gseer_evidence_class(JSONB);
DROP FUNCTION IF EXISTS public.gseer_evidence_kinds(JSONB);
DROP INDEX IF EXISTS ix_asset_evidence_class;
DROP TABLE IF EXISTS asset_evidence;
