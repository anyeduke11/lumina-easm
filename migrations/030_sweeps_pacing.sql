-- P0-5（M4 审查缺口销账）：sweep 执行行的限速消费留痕落 PG。
-- rate_limit=本次消费的授权限速（req/s；0=未配置/不限）；paced_ms=本次累计限速等待毫秒
-- （per-run 归属——跨 sweep 不得累计，否则取证失真）。此前仅内存后端携带这两字段，
-- PG 侧静默丢失=双后端漂移（跨进程/Workflow 复盘看不到限速是否被消费）。
BEGIN;

ALTER TABLE sweeps ADD COLUMN IF NOT EXISTS rate_limit integer NOT NULL DEFAULT 0;
ALTER TABLE sweeps ADD COLUMN IF NOT EXISTS paced_ms bigint NOT NULL DEFAULT 0;

COMMIT;
