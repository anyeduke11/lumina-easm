-- M4-03 / 021：排查任务单落 PG（FR-MON-003；SRS P0 验收「触发后生成对应排查任务」）。
-- 为什么：任务单是「资产变更/POC 触发→重扫」这一合规动作链的触发记录——随进程蒸发
-- 等于触发链断裂不可审计（与 notify_log 出口去重、evalset 门禁证据同口径：跨重启可查）。
-- 契约：id=RT-<sha12(tenant|asset|trigger|ts)>；幂等=同源 pending 单收敛刷新（UPDATE），
-- 不开新行；闭环（done）后可再触发=新行。部分唯一索引兜底同源 pending 单唯一性。
BEGIN;

CREATE TABLE IF NOT EXISTS monitor_tasks (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  asset_id   text NOT NULL,
  asset_name text NOT NULL DEFAULT '',
  trigger    text NOT NULL,
  reason     text NOT NULL DEFAULT '',
  status     text NOT NULL DEFAULT 'pending',
  by_whom    text NOT NULL DEFAULT '',
  note       text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  done_at    timestamptz
);
-- 同源未闭环单唯一（租户+资产+触发源）：pending 只允许一张，收敛刷新不开新行
CREATE UNIQUE INDEX IF NOT EXISTS uq_monitor_tasks_open
  ON monitor_tasks(tenant_id, asset_id, trigger) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_monitor_tasks_tenant ON monitor_tasks(tenant_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON monitor_tasks TO easm_app;

COMMIT;
