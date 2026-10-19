-- V-10 / 017：ledger_items 增加 refute 列（零误报门2 的反证记录持久化）。
-- 为什么：与 xchk（015）同类——ledger PG 实现是显式列，Item 新增字段不加列即被静默
-- 丢弃（内存模式正常=双后端漂移）。门2 判据（「哪些事实能否定它 + 核查结果」）
-- 必须跨重启可查，否则降级理由不可复算。
-- Update 同样带列：状态迁移不得抹掉反证记录。
BEGIN;

ALTER TABLE ledger_items ADD COLUMN IF NOT EXISTS refute jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMIT;
