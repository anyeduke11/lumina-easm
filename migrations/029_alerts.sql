-- 029 · Finding 告警（Phase 2 / FR-MON-002）
BEGIN;

CREATE TABLE IF NOT EXISTS alerts (
  id          text PRIMARY KEY,
  entity_id   text NOT NULL,
  finding_id  text NOT NULL,
  severity    text NOT NULL,
  title       text NOT NULL,
  status      text NOT NULL DEFAULT 'open',
  source      text NOT NULL DEFAULT 'finding',
  created_at  timestamptz NOT NULL DEFAULT now(),
  acked_at    timestamptz,
  acked_by    text NOT NULL DEFAULT '',
  CONSTRAINT alerts_status CHECK (status IN ('open','ack','closed')),
  UNIQUE (entity_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_entity ON alerts(entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(entity_id, status);

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_entity ON alerts;
CREATE POLICY alerts_entity ON alerts
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON alerts TO easm_app;

COMMIT;
