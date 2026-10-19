-- M3-E / 019：评测集与反馈门禁落 PG（WP-M3-06 / FR-VRF-004 / AIL-7 / NFR-MNT-005）。
-- 为什么：评测样本与运行记录是「指标不达标不放量」门禁的合规证据面——随进程蒸发
-- 等于门禁形同虚设（与 015/017/018 同口径：评测结论必须跨重启可查、可复核）。
-- 契约：evalset_samples 按确定性 ID（EV-<sha12>）幂等，PutSample 不覆盖既有标注；
-- relabels 追加式（二次标注不改写历史）；evalset_runs payload=完整 Run 单一真相，
-- ts/total 列仅承担排序与统计索引。
BEGIN;

CREATE TABLE IF NOT EXISTS evalset_samples (
  id          text PRIMARY KEY,
  tenant_id   text NOT NULL,
  kind        text NOT NULL,
  content     text NOT NULL,
  expected    boolean NOT NULL,
  expected_by text NOT NULL DEFAULT '',
  evidence_ref text NOT NULL DEFAULT '',
  ledger_id   text NOT NULL DEFAULT '',
  source      text NOT NULL DEFAULT 'manual',
  relabels    jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evalset_samples_tenant ON evalset_samples(tenant_id, id);

CREATE TABLE IF NOT EXISTS evalset_runs (
  id        text PRIMARY KEY,
  tenant_id text NOT NULL,
  subject   text NOT NULL,
  total     integer NOT NULL DEFAULT 0,
  payload   jsonb NOT NULL,
  ts        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evalset_runs_tenant ON evalset_runs(tenant_id, ts DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON evalset_samples, evalset_runs TO easm_app;

COMMIT;
