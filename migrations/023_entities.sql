-- 023 · 单用户监管形态：被监管单位（entity）数据域视图
-- 设计口径：内部 tenant 表/tenant_id 列保留为 legacy 实现；对外与报表层统一称 entity。
-- 视图只读，不改变既有 RLS/GRANT；写路径仍走 tenants 表（POST/PATCH /v1/entities 别名）。
BEGIN;

CREATE OR REPLACE VIEW regulated_entities AS
SELECT id,
       name,
       short,
       industry,
       level,
       plan,
       root_domains,
       cidrs,
       contact,
       region,
       signed_at,
       contract_end,
       theme_color,
       status,
       created_at
  FROM tenants;

COMMENT ON VIEW regulated_entities IS
  '被监管单位数据域视图；id 即 entity_id，底层 tenant_id 为 legacy 列';

GRANT SELECT ON regulated_entities TO easm_app;

COMMIT;
