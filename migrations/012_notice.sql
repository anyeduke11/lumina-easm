-- WP-M2-04 / 012：线索通报落 PG（CR-002「每一次线索通报的目标、材料哈希与时间戳」的持久载体；
-- 过渡形态下通报单号+材料+回执必须跨重启可查——报送是对外承诺动作，蒸发=合规缺口）。
-- 三要素（target/material_hash/created_at）随首份写入锁定；回执只追加（MarkReceipt）。
BEGIN;

CREATE TABLE IF NOT EXISTS notices (
  id            text PRIMARY KEY,           -- NB-<sha12(tenant|ledger|target)>：单号即归档键
  tenant_id     text NOT NULL,
  ledger_id     text NOT NULL,
  target        text NOT NULL CHECK (target IN ('属地公安机关','省网络与信息安全通报中心')),
  status        text NOT NULL CHECK (status IN ('待报送','已报送')),
  material_hash text NOT NULL,              -- CR-002 材料哈希
  material_ref  text NOT NULL,              -- 可回溯锚点（证据对象或行内固化）
  receipt_no    text,                       -- 报送回执号（人工投递后回填）
  submitted_at  timestamptz,
  n             jsonb NOT NULL,             -- Notice 全量（含材料文本，过渡=行内双写）
  created_at    timestamptz NOT NULL,       -- CR-002 时间戳
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notices_tenant_status ON notices(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_notices_tenant_ledger ON notices(tenant_id, ledger_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON notices TO easm_app;

-- CR-002 纵深防御：三要素（单号/租户/目标/材料哈希/ref/发起时间）一经写入即锁定，
-- 连裸 SQL UPDATE 也被拒（应用层 Update 语句本就不写这些列，此处=第二道闸）。
CREATE OR REPLACE FUNCTION notices_lock_immutable() RETURNS trigger AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.target IS DISTINCT FROM OLD.target
     OR NEW.material_hash IS DISTINCT FROM OLD.material_hash
     OR NEW.material_ref IS DISTINCT FROM OLD.material_ref
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'notices: CR-002 三要素不可改写（单号/目标/材料哈希/时间戳锁定）';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notices_immutable ON notices;
CREATE TRIGGER trg_notices_immutable BEFORE UPDATE ON notices FOR EACH ROW
  EXECUTE FUNCTION notices_lock_immutable();

COMMIT;
