-- WP-M1 / 009：告警发送历史落 PG（notify 出口去重跨重启 + 监管留痕）。
-- dedup_key=完整键「channel|alertKey」；唯一索引=留痕幂等（重放不复制）。
BEGIN;

CREATE TABLE IF NOT EXISTS notify_log (
  id         bigserial PRIMARY KEY,
  channel    text NOT NULL,
  dedup_key  text NOT NULL UNIQUE,
  alert_key  text NOT NULL,
  sent_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notify_log_channel ON notify_log(channel);

GRANT SELECT, INSERT, UPDATE, DELETE ON notify_log TO easm_app;
GRANT USAGE, SELECT ON SEQUENCE notify_log_id_seq TO easm_app;

COMMIT;
