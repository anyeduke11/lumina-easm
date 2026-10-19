-- V-5 / 015：ledger_items 增加 xchk 列（零误报门1 的独立信源清单持久化）。
-- 为什么：ledger PG 实现是显式列（非 JSONB），Item 新增字段若不加列即被静默丢弃——
-- 实测缺陷（V-4/V-5 开发轮 live 取证发现：双信源严重级仍被门1 降级、xchk 回读为空）。
-- Update 也必须带列：否则状态迁移（SetStatus）会把交叉信源抹掉=门1 判据丢失。
BEGIN;

ALTER TABLE ledger_items ADD COLUMN IF NOT EXISTS xchk text[] NOT NULL DEFAULT '{}';

COMMIT;
