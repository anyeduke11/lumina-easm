-- WP-V4 / 014：人工复核面落 PG（candidate.unsupported + ownership 复核队列）。
-- 为什么：两张队列都是「不静默丢弃」的 fail-loud 界面——拒绝的候选行与疑似/无关样本
-- 是复核锚点，随进程蒸发即等于把问题悄悄扔掉（与 006~013 已落 PG 的各域口径不一致）。
-- 契约：ownership_queue 按 (tenant_id, domain) 幂等（保留原 seq，复核编号跨重启稳定），
-- Resolve 只置状态+留痕（行保留=复核历史可追溯）；candidate_unsupported 按 (line,error)
-- 去重键幂等（重放/重试不重复入队）。
BEGIN;

CREATE TABLE IF NOT EXISTS ownership_queue (
  seq         bigserial PRIMARY KEY,
  tenant_id   text NOT NULL,
  domain      text NOT NULL,
  item        jsonb NOT NULL,
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','resolved')),
  resolved_by text,
  resolved_at timestamptz,
  ts          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, domain)
);
CREATE INDEX IF NOT EXISTS idx_ownership_queue_pending ON ownership_queue(tenant_id, status, seq);

CREATE TABLE IF NOT EXISTS candidate_unsupported (
  key     text PRIMARY KEY,          -- sha256(line|error)：同原文同原因=同一复核项
  ts      timestamptz NOT NULL DEFAULT now(),
  line    text NOT NULL,
  error   text NOT NULL,
  channel text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_candidate_unsupported_ts ON candidate_unsupported(ts, key);

GRANT SELECT, INSERT, UPDATE, DELETE ON ownership_queue, candidate_unsupported TO easm_app;
GRANT USAGE, SELECT ON SEQUENCE ownership_queue_seq_seq TO easm_app;

COMMIT;
