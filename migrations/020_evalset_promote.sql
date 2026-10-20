-- ENH-03 / 020：AI 判敏灰度放量留痕（M3-E 动作面执行点，消费 evalset/gate 判定）。
-- 为什么：放量是可审计动作——谁在哪个门禁判定下放量必须跨重启可查可对账（AIL-7
-- 「指标不达标不放量」的动作面证据；与 019 同口径：门禁证据面不得随进程蒸发）。
-- 契约：id=EP-<sha12>（确定性含 ts）；run_id=放行依据的评测运行；thresholds=放行时口径快照。
BEGIN;

CREATE TABLE IF NOT EXISTS evalset_promotes (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL,
  run_id     text NOT NULL,
  gate_allow boolean NOT NULL,
  reasons    jsonb NOT NULL DEFAULT '[]'::jsonb,
  thresholds jsonb NOT NULL,
  by_whom    text NOT NULL DEFAULT '',
  note       text NOT NULL DEFAULT '',
  ts         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evalset_promotes_tenant ON evalset_promotes(tenant_id, ts DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON evalset_promotes TO easm_app;

COMMIT;
