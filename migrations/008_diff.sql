-- WP-M1 / 008：资产快照落 PG（FR-MON-002 增量 Diff 的跨扫描基线；平台级数据，同 knowledge 不设 RLS）。
BEGIN;

CREATE TABLE IF NOT EXISTS asset_snapshots (
  tenant_id   text NOT NULL,
  asset_id    text NOT NULL,
  fp          text NOT NULL,          -- 确定性指纹（monitor.fp 口径）
  captured_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, asset_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_snapshots TO easm_app;

COMMIT;
