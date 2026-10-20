-- 028 · 资产状态机（Phase 2 / FR-AST-002）
BEGIN;

ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS state_reason text NOT NULL DEFAULT '';
ALTER TABLE inventory_assets ADD COLUMN IF NOT EXISTS state_changed_at timestamptz;
UPDATE inventory_assets SET state_changed_at = last_seen WHERE state_changed_at IS NULL;

COMMIT;
