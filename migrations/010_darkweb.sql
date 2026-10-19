-- WP-M2-02 本体落库（010_darkweb）：① 租户归属指纹基线（FR-CHN-005 比对基准，跨重启不丢——
-- 暗网样本归属判定的判据本身必须持久，否则重启后所有样本退化为「基线缺失→全疑似」）
-- ② 线索包（FR-CHN-008 通报材料：包体 JSONB + content_hash 防篡改基线；重放同 package_id
--   ON CONFLICT DO NOTHING=WORM 首次语义，与证据对象存储同口径——通报材料不可被后续重扫改写）。
BEGIN;

CREATE TABLE IF NOT EXISTS ownership_fingerprints (
  tenant_id  text PRIMARY KEY,
  fp         jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lead_packages (
  package_id   text PRIMARY KEY,          -- LPK-<sha12(tenant|样本ID有序集)>：同输入=同包
  tenant_id    text NOT NULL,
  content_hash text NOT NULL,             -- 整包规范内容 sha256（防篡改基线）
  evidence_ref text,                      -- 证据对象存储 ref（file|minio；C-5 回溯锚点）
  pkg          jsonb NOT NULL,            -- LeadPackage 全量（items/chains/scale）
  generated_at timestamptz NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lead_packages_tenant ON lead_packages(tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ownership_fingerprints TO easm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON lead_packages TO easm_app;

COMMIT;
