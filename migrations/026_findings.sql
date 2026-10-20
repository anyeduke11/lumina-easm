-- 026 · Finding 生命周期（Phase 1 / FR-LGR/FR-VRF）
-- Finding 是暴露结论的事实源；台账是后续合规投影。confirmed 必须有证据；closed 必须有复测证据。
BEGIN;

CREATE TABLE IF NOT EXISTS findings (
  id            text PRIMARY KEY,
  entity_id     text NOT NULL,
  asset_id      text NOT NULL,
  type          text NOT NULL,
  title         text NOT NULL,
  lifecycle     text NOT NULL DEFAULT 'new',
  severity      text NOT NULL,
  confidence    numeric(4,3) NOT NULL DEFAULT 0.5,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  source        text NOT NULL,
  rule_id       text,
  evidence_refs text[] NOT NULL DEFAULT '{}',
  note          text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT findings_lifecycle CHECK (lifecycle IN
    ('new','triaged','validating','confirmed','remediating','verified','closed',
     'false_positive','risk_accepted','duplicate')),
  CONSTRAINT findings_severity CHECK (severity IN ('critical','high','medium','low','info'))
);
CREATE INDEX IF NOT EXISTS idx_findings_entity ON findings(entity_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(entity_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_lifecycle ON findings(entity_id, lifecycle);

CREATE TABLE IF NOT EXISTS finding_validations (
  id           bigserial PRIMARY KEY,
  finding_id   text NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  method       text NOT NULL,
  result       text NOT NULL,
  evidence_ref text,
  note         text NOT NULL DEFAULT '',
  by_user      text NOT NULL,
  at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_validations_finding ON finding_validations(finding_id, at);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS findings_entity ON findings;
CREATE POLICY findings_entity ON findings
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

ALTER TABLE finding_validations ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_validations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_validations_entity ON finding_validations;
CREATE POLICY finding_validations_entity ON finding_validations
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR EXISTS (SELECT 1 FROM findings f WHERE f.id = finding_id
                    AND f.entity_id = current_setting('easm.tenant_id', true)));

GRANT SELECT, INSERT, UPDATE, DELETE ON findings TO easm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON finding_validations TO easm_app;
GRANT USAGE, SELECT ON SEQUENCE finding_validations_id_seq TO easm_app;

COMMIT;
