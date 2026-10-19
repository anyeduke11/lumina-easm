-- WP-M1 / 006：sweep 行落 PG（ENH-01 Temporal 前置——server 与 worker 跨进程共享事实源）。
-- 平台级任务台账（同 ledger：非租户隔离数据，不设 RLS；行含 COV-* 覆盖度快照）。
BEGIN;

CREATE TABLE IF NOT EXISTS sweeps (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  phases     text[] NOT NULL DEFAULT '{}',
  status     text NOT NULL,
  steps      jsonb NOT NULL DEFAULT '[]',   -- [{phase,step,status,outputs,new_issues}]
  findings   integer NOT NULL DEFAULT 0,
  error      text NOT NULL DEFAULT '',
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at   timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sweeps_tenant ON sweeps(tenant_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON sweeps TO easm_app;

COMMIT;
