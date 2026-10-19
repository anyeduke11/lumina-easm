-- WP-M0-03 · PostgreSQL 基座（FR-TEN-001 / FR-AST-001 / FR-TEN-005）
BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
  id           text PRIMARY KEY,
  name         text NOT NULL,
  short        text,
  industry     text,
  level        text,
  plan         text,
  root_domains text[] DEFAULT '{}',
  cidrs        text[] DEFAULT '{}',
  contact      text,
  region       text,
  signed_at    timestamptz,
  contract_end timestamptz,
  theme_color  text,
  status       text NOT NULL DEFAULT 'active',  -- active / suspended
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assets (
  id         text PRIMARY KEY,
  tenant_id  text NOT NULL REFERENCES tenants(id),
  name       text NOT NULL,
  type       text NOT NULL,
  type_label text,
  ip         text,
  risk       text NOT NULL DEFAULT 'info',
  exp        int  NOT NULL DEFAULT 0 CHECK (exp BETWEEN 0 AND 100),
  owner      text NOT NULL DEFAULT '未归属',
  found      timestamptz NOT NULL DEFAULT now(),
  status     text NOT NULL DEFAULT '在用',      -- 在用/闲置/废弃
  beian      text NOT NULL DEFAULT '未备案',    -- 已备案/未备案/备案中
  source     text,
  biz        text,
  tags       text[] DEFAULT '{}',
  ai         text,
  ports      int[]  DEFAULT '{}',
  tech       text[] DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);

-- FR-TEN-005 / NFR-SEC-004：租户行级隔离（应用连接需 SET easm.tenant_id）
-- NULL 或 '' = 平台穿透模式（Service 层已判权，仅受控代码路径使用）；
-- 设置非空 GUC 后强制单租户。注意：本地 set_config 提交后 current_setting 返回 ''，
-- 因此穿透判定必须同时覆盖 IS NULL 与 = ''。
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS assets_tenant_isolation ON assets;
CREATE POLICY assets_tenant_isolation ON assets
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR tenant_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR tenant_id = current_setting('easm.tenant_id', true));

-- NFR-SEC-006 / CR-001：审计日志（仅追加；生产落 WORM/ClickHouse）
CREATE TABLE IF NOT EXISTS audit_logs (
  id         bigserial PRIMARY KEY,
  ts         timestamptz NOT NULL DEFAULT now(),
  actor      text NOT NULL,
  action     text NOT NULL,
  tenant_id  text,
  resource   text,
  result     text NOT NULL CHECK (result IN ('allow', 'deny')),
  request_id text
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts ON audit_logs(tenant_id, ts);
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;

COMMIT;
