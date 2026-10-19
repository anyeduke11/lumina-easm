-- WP-M1 / 007：授权范围落 PG（ENH-01 worker 与 server 共享 auth_scope 的硬前提；
-- 同时销账：server 重启不再丢授权——一票否决⑥的数据面 durability）。
BEGIN;

CREATE TABLE IF NOT EXISTS auth_scopes (
  tenant_id   text PRIMARY KEY,
  scope       jsonb NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_scopes TO easm_app;

COMMIT;
