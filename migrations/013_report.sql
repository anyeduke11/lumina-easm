-- WP-M2-09 / V-3：报告中心历史落 PG（FR-RPT-001~003 的持久载体）。
-- 为什么：报告=对外交付物（切客户全变 A-05 + 内容哈希可复算），MemStore 重启清空
-- 意味着「生成过的报告」随进程蒸发——与 sweeps/authz/workorders/notices/darkweb
-- 均已落 PG 的持久性口径不一致（审查 P2-1）。整行 JSONB（同 011/012 型 C-6 契约）。
-- 报告为不可变快照：同参数同窗重放=覆盖刷新（编号幂等，内容取最新事实），故仅 UPSERT 无 UPDATE 语义需求。
BEGIN;

CREATE TABLE IF NOT EXISTS reports (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  r          jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant ON reports(tenant_id, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON reports TO easm_app;

COMMIT;
