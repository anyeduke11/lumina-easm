-- 025 · EASM 资产身份与观察流（Phase 1 / FR-AST/FR-DSC）
-- 规范资产 + 别名 + 原始观察（append-only）。entity_id 是数据域；RLS 以
-- current_setting('easm.tenant_id') 强制（应用层 withTenant 设置；空=平台穿透，仅受控路径）。
BEGIN;

CREATE TABLE IF NOT EXISTS inventory_assets (
  id            text PRIMARY KEY,
  entity_id     text NOT NULL,
  kind          text NOT NULL,
  canonical_key text NOT NULL,
  display_name  text NOT NULL,
  state         text NOT NULL DEFAULT 'candidate',
  confidence    numeric(4,3) NOT NULL DEFAULT 0.5,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  sources       text[] NOT NULL DEFAULT '{}',
  attributes    jsonb NOT NULL DEFAULT '{}',
  UNIQUE (entity_id, kind, canonical_key)
);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_entity ON inventory_assets(entity_id, last_seen DESC);

CREATE TABLE IF NOT EXISTS inventory_aliases (
  entity_id  text NOT NULL,
  asset_id   text NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
  alias_key  text NOT NULL,
  alias_type text NOT NULL DEFAULT 'value',
  source_id  text,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (entity_id, asset_id, alias_key)
);
CREATE INDEX IF NOT EXISTS idx_inventory_aliases_lookup ON inventory_aliases(entity_id, alias_key);

CREATE TABLE IF NOT EXISTS inventory_observations (
  id           text PRIMARY KEY,
  entity_id    text NOT NULL,
  asset_id     text NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
  asset_key    text NOT NULL,
  source_id    text NOT NULL,
  observed_at  timestamptz NOT NULL,
  raw_ref      text,
  payload_hash text NOT NULL,
  payload      jsonb NOT NULL DEFAULT '{}',
  UNIQUE (entity_id, payload_hash)
);
CREATE INDEX IF NOT EXISTS idx_inventory_obs_asset ON inventory_observations(entity_id, asset_id, observed_at DESC);

ALTER TABLE inventory_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inventory_assets_entity ON inventory_assets;
CREATE POLICY inventory_assets_entity ON inventory_assets
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

ALTER TABLE inventory_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_aliases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inventory_aliases_entity ON inventory_aliases;
CREATE POLICY inventory_aliases_entity ON inventory_aliases
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

ALTER TABLE inventory_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventory_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inventory_observations_entity ON inventory_observations;
CREATE POLICY inventory_observations_entity ON inventory_observations
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_assets TO easm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_aliases TO easm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_observations TO easm_app;

COMMIT;
