-- 024 · 单用户高危动作确认（FR-LGR-005 / CR-001 / AX-5）
-- 单用户没有第二个人可做双人审批；本表记录「可追溯的自我确认」：
-- 动作/资源/实体/方式/理由/范围哈希/有效期/消费时刻。确认不是审批。
BEGIN;

CREATE TABLE IF NOT EXISTS confirmations (
  id          text PRIMARY KEY,
  entity_id   text NOT NULL,
  action      text NOT NULL,
  resource    text NOT NULL,
  operator_id text NOT NULL,
  method      text NOT NULL,
  reason      text NOT NULL,
  scope_hash  text,
  ts          timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_confirmations_entity_ts ON confirmations(entity_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_confirmations_unconsumed ON confirmations(expires_at) WHERE consumed_at IS NULL;

COMMENT ON TABLE confirmations IS '单用户高危动作自我确认；每次消费一次性，审计可回溯';

GRANT SELECT, INSERT, UPDATE ON confirmations TO easm_app;

COMMIT;
