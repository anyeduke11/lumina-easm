-- V-9 / 016：候选摄取留痕落 PG（candidate.AcceptedStore）。
-- 为什么：「摄取过什么」是可审计事实（工具适配层/采集器投喂历史）——重启后只余计数
-- 不留记录=摄取行为不可追溯（与 014 unsupported 复核面同口径，一进一出都要留痕）。
-- 去重键 = sha256(原始行)：同一条 JSONL 重复摄取=同一留痕（重放/重试不翻倍）。
-- 仅追加语义：保留原始行供回溯（C-5）；应用层无改写/删除路径（DELETE 授权仅供测试清场）。
BEGIN;

CREATE TABLE IF NOT EXISTS candidate_accepted (
  key         text PRIMARY KEY,
  tenant_id   text NOT NULL,
  kind        text NOT NULL,
  sub_code    text NOT NULL,
  channel     text NOT NULL,
  ts          timestamptz NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now(),
  line        text NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidate_accepted_tenant ON candidate_accepted(tenant_id, accepted_at);

GRANT SELECT, INSERT, DELETE ON candidate_accepted TO easm_app;

COMMIT;
