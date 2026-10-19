-- S-2 / 018：ledger_items 增加 verifs 列（零误报门3 的验证记录持久化）。
-- 为什么：闭环必须可验证（AX-3+AX-4）——每次 Verify 的方法/结果/证据引用/操作人
-- 都要跨重启可查，否则「已闭环」只是内存里的一个状态字。与 xchk/refute（015/017）同类：
-- 显式列不同步即静默丢字段。
BEGIN;

ALTER TABLE ledger_items ADD COLUMN IF NOT EXISTS verifs jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMIT;
