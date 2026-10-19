-- WP-M1 / 005：漏洞库/情报库落 PG（F9.1/F9.3；批三遗留「重启即失」销账）。
-- 平台级全局知识库（同 ledger_items：非租户数据，不设 RLS；写入先到先得=UPSERT DO NOTHING）。
BEGIN;

CREATE TABLE IF NOT EXISTS vuln_entries (
  cve      text PRIMARY KEY,
  title    text NOT NULL DEFAULT '',
  cvss     double precision NOT NULL DEFAULT 0 CHECK (cvss >= 0 AND cvss <= 10),
  epss     double precision NOT NULL DEFAULT 0 CHECK (epss >= 0 AND epss <= 1),
  severity text NOT NULL DEFAULT '',
  category text NOT NULL DEFAULT '',
  tags     text[] NOT NULL DEFAULT '{}',
  descr    text NOT NULL DEFAULT '',
  fix      text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS intel_entries (
  key        text PRIMARY KEY, -- type|lower(value)：与 intel.Key 同口径（C-6）
  type       text NOT NULL CHECK (type IN ('domain','ip','url','md5','sha256','email')),
  value      text NOT NULL,
  threat     text NOT NULL DEFAULT '',
  family     text NOT NULL DEFAULT '',
  confidence double precision NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
  source     text NOT NULL DEFAULT '',
  tags       text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_intel_entries_type ON intel_entries(type);

GRANT SELECT, INSERT, UPDATE, DELETE ON vuln_entries, intel_entries TO easm_app;

COMMIT;
