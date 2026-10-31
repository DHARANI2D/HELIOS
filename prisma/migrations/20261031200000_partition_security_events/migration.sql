-- security_events becomes a table partitioned by month on "timestamp".
-- Postgres wants the partition key in every unique constraint, so the
-- primary key is (id, timestamp) and a source's event id is unique per
-- integration and timestamp (a resend has the same timestamp).
ALTER TABLE "security_events" RENAME TO "security_events_unpartitioned";
ALTER TABLE "security_events_unpartitioned" RENAME CONSTRAINT "security_events_pkey" TO "security_events_unpartitioned_pkey";
ALTER TABLE "security_events_unpartitioned" RENAME CONSTRAINT "security_events_caseId_fkey" TO "security_events_unpartitioned_caseId_fkey";
ALTER TABLE "security_events_unpartitioned" RENAME CONSTRAINT "security_events_tenantId_fkey" TO "security_events_unpartitioned_tenantId_fkey";
ALTER INDEX "security_events_timestamp_idx" RENAME TO "security_events_unpartitioned_timestamp_idx";
ALTER INDEX "security_events_caseId_idx" RENAME TO "security_events_unpartitioned_caseId_idx";
ALTER INDEX "security_events_batchId_idx" RENAME TO "security_events_unpartitioned_batchId_idx";
ALTER INDEX "security_events_tenantId_timestamp_idx" RENAME TO "security_events_unpartitioned_tenantId_timestamp_idx";
ALTER INDEX "security_events_tenantId_classUid_timestamp_idx" RENAME TO "security_events_unpartitioned_tenantId_classUid_timestamp_idx";
ALTER INDEX "security_events_integrationId_sourceEventId_key" RENAME TO "security_events_unpartitioned_integrationId_sourceEventId_key";

CREATE TABLE "security_events" (LIKE "security_events_unpartitioned" INCLUDING DEFAULTS INCLUDING GENERATED) PARTITION BY RANGE ("timestamp");
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_pkey" PRIMARY KEY ("id", "timestamp");
CREATE UNIQUE INDEX "security_events_integrationId_sourceEventId_timestamp_key" ON "security_events"("integrationId", "sourceEventId", "timestamp");
CREATE INDEX "security_events_timestamp_idx" ON "security_events"("timestamp");
CREATE INDEX "security_events_caseId_idx" ON "security_events"("caseId");
CREATE INDEX "security_events_batchId_idx" ON "security_events"("batchId");
CREATE INDEX "security_events_tenantId_timestamp_idx" ON "security_events"("tenantId", "timestamp");
CREATE INDEX "security_events_tenantId_classUid_timestamp_idx" ON "security_events"("tenantId", "classUid", "timestamp");
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Anything outside the monthly partitions lands here; the job keeps the
-- months ahead created (lib/retention/partitions.ts).
CREATE TABLE "security_events_default" PARTITION OF "security_events" DEFAULT;

-- A partition for every month the existing events span (at most the last
-- two years; older rows, past any retention, wait in the default partition
-- for the retention job) through three months ahead. Each carries the same
-- row-level policy as the parent.
DO $$
DECLARE
  first_month date := greatest(date_trunc('month', coalesce((SELECT min("timestamp") FROM "security_events_unpartitioned"), now())), date_trunc('month', now() - interval '24 months'))::date;
  last_month date := (date_trunc('month', now()) + interval '3 months')::date;
  m date;
  t text;
BEGIN
  m := first_month;
  WHILE m <= last_month LOOP
    t := 'security_events_' || to_char(m, 'YYYY_MM');
    EXECUTE format('CREATE TABLE %I PARTITION OF "security_events" FOR VALUES FROM (%L) TO (%L)', t, m, (m + interval '1 month')::date);
    m := (m + interval '1 month')::date;
  END LOOP;
  FOR t IN SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid WHERE i.inhparent = '"security_events"'::regclass LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true)) WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))$p$, t);
  END LOOP;
END $$;

INSERT INTO "security_events" SELECT * FROM "security_events_unpartitioned";
DROP TABLE "security_events_unpartitioned";

-- Row-level isolation on the parent, as before.
ALTER TABLE "security_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "security_events" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "security_events"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
