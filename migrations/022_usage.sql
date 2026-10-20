-- M4-07 / 022：模型调用成本计量与预算（FR-HRN-10 P1）。
-- 为什么：AI 面按租户的 token 消耗=成本治理与预算告警的事实源——随进程蒸发等于计量失真；
-- 预算行（含当月告警标记）跨重启可查（与 notify_log/monitor_tasks 同口径）。
-- 契约：usage_events 追加式（只 INSERT 不 UPDATE，计量=事实）；usage_budgets 租户一行
-- （预算口径变更即 UPDATE + 清当月告警标记）；汇总按 [since,until) 区间聚合。
BEGIN;

CREATE TABLE IF NOT EXISTS usage_events (
  id                text PRIMARY KEY,
  tenant_id         text NOT NULL,
  feature           text NOT NULL,
  model             text NOT NULL,
  prompt_tokens     bigint NOT NULL DEFAULT 0,
  completion_tokens bigint NOT NULL DEFAULT 0,
  total_tokens      bigint NOT NULL DEFAULT 0,
  ts                timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_usage_events_tenant ON usage_events(tenant_id, ts DESC);

CREATE TABLE IF NOT EXISTS usage_budgets (
  tenant_id     text PRIMARY KEY,
  monthly_tokens bigint NOT NULL,
  by_whom       text NOT NULL DEFAULT '',
  updated_at    timestamptz NOT NULL DEFAULT now(),
  alert_month   text NOT NULL DEFAULT ''  -- 当月已告警标记（口径变更即清）
);

GRANT SELECT, INSERT, UPDATE, DELETE ON usage_events, usage_budgets TO easm_app;

COMMIT;
