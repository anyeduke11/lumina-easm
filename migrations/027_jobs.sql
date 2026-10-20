-- 027 · Job Queue（Phase 1 / 执行平面）
-- PG 表 + SKIP LOCKED 租约；idempotency_key 去重；worker 以 entity_id='' 平台模式租约。
BEGIN;

CREATE TABLE IF NOT EXISTS jobs (
  id              text PRIMARY KEY,
  entity_id       text NOT NULL,
  kind            text NOT NULL,
  payload         jsonb NOT NULL DEFAULT '{}',
  state           text NOT NULL DEFAULT 'queued',
  priority        int NOT NULL DEFAULT 0,
  idempotency_key text NOT NULL UNIQUE,
  attempts        int NOT NULL DEFAULT 0,
  max_attempts    int NOT NULL DEFAULT 3,
  lease_owner     text,
  lease_until     timestamptz,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  started_at      timestamptz,
  finished_at     timestamptz,
  next_run_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT jobs_state CHECK (state IN ('queued','leased','running','succeeded','failed','dead','canceled'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(state, next_run_at, priority DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_entity ON jobs(entity_id, created_at DESC);

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS jobs_entity ON jobs;
CREATE POLICY jobs_entity ON jobs
  USING (coalesce(current_setting('easm.tenant_id', true), '') = ''
         OR entity_id = current_setting('easm.tenant_id', true))
  WITH CHECK (coalesce(current_setting('easm.tenant_id', true), '') = ''
              OR entity_id = current_setting('easm.tenant_id', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO easm_app;

COMMIT;
