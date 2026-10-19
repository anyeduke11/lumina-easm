-- WP-M0-03 · 应用角色（FR-TEN-005 / NFR-SEC-004）
-- easm_app：无 SUPERUSER、无 BYPASSRLS —— RLS 对其强制生效（001 已 FORCE）。
BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'easm_app') THEN
    -- 本地开发占位口令（与 Makefile EASM_APP_DSN 掩码约定一致）；生产部署必须由编排注入强口令
    CREATE ROLE easm_app LOGIN PASSWORD 'easm-***';
  END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO easm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO easm_app;    -- 行可见性由 RLS 控制
GRANT INSERT, SELECT ON audit_logs TO easm_app;                -- 仅追加：无 UPDATE/DELETE/TRUNCATE
GRANT USAGE, SELECT ON SEQUENCE audit_logs_id_seq TO easm_app;

COMMIT;
