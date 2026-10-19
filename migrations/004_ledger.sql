-- WP-M1 / 004：风险台账落 PG（FR-LGR / DR-02；替换 MVP 内存 store）
BEGIN;

CREATE TABLE IF NOT EXISTS ledger_items (
  id       text PRIMARY KEY,
  tenant_id text NOT NULL REFERENCES tenants(id),
  phase    text NOT NULL CHECK (phase IN ('P1','P2','P3','P4','P5')),
  cat      text NOT NULL CHECK (cat IN ('系统架构类','代码密码类','业务经营类')),
  asset    text NOT NULL DEFAULT '',
  title    text NOT NULL,
  lv       text NOT NULL CHECK (lv IN ('严重','高','中')),
  src      text NOT NULL,
  found    timestamptz NOT NULL,
  action   text NOT NULL,
  owner    text NOT NULL,
  due      timestamptz NOT NULL,
  st       text NOT NULL DEFAULT 'open' CHECK (st IN ('open','doing','closed','notify')),
  notify   boolean NOT NULL DEFAULT false,
  note     text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_status ON ledger_items(tenant_id, st);

GRANT SELECT, INSERT, UPDATE, DELETE ON ledger_items TO easm_app;

COMMIT;
