-- 0030_hostname_prefix.down.sql — remove the hostname prefix index.
DROP INDEX IF EXISTS ix_assets_hostname_prefix;
