-- WP-M2-03 / 011：平台处置工单落 PG（FR-CHN-004 五态跟踪的持久载体；
-- server/worker 共享=重启不丢工单，跟催与下架证据不可随进程蒸发）。
-- 整行 JSONB（同 006/007 型 C-6 契约）+ status/tenant 独立列供催办台筛选。
BEGIN;

CREATE TABLE IF NOT EXISTS work_orders (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  status     text NOT NULL CHECK (status IN ('待整改','处置中','已通报平台','已下架','已处置')),
  wo         jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_work_orders_tenant_status ON work_orders(tenant_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON work_orders TO easm_app;

COMMIT;
