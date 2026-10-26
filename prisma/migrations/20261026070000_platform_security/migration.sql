-- AlterTable
ALTER TABLE "users" ADD COLUMN     "mfaEnabledAt" TIMESTAMP(3),
ADD COLUMN     "mfaLastStep" INTEGER,
ADD COLUMN     "mfaRecoveryHashes" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "mfaSecretCipher" TEXT;

-- CreateTable
CREATE TABLE "tenant_keys" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "wrapped" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "retiredAt" TIMESTAMP(3),
    "destroyedAt" TIMESTAMP(3),

    CONSTRAINT "tenant_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tenant_keys_tenantId_version_key" ON "tenant_keys"("tenantId", "version");

-- AddForeignKey
ALTER TABLE "tenant_keys" ADD CONSTRAINT "tenant_keys_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Row-level tenant isolation. A transaction that sets helios.tenant_id
-- (lib/tenant-db.ts, for client sessions and client API tokens) sees and
-- writes only that client's rows; without it (staff, background jobs) the
-- policies allow everything. FORCE applies them to the table owner too, so
-- the app must not connect as a superuser (superusers bypass RLS).
ALTER TABLE "cases" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "cases" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "cases"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "security_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "security_events" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "security_events"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "endpoints" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "endpoints" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "endpoints"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "integrations" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "integrations" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "integrations"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "response_actions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "response_actions" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "response_actions"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "ai_runs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ai_runs" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ai_runs"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "agents" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "agents" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "agents"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "org_policies" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "org_policies" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "org_policies"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "policy_allowlist" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "policy_allowlist" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "policy_allowlist"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "autonomy_levels" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "autonomy_levels" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "autonomy_levels"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "ai_decision_outcomes" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ai_decision_outcomes" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ai_decision_outcomes"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "tenant_ai_policies" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tenant_ai_policies" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "tenant_ai_policies"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "ingest_batches" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ingest_batches" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ingest_batches"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "ingest_dead_letters" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ingest_dead_letters" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ingest_dead_letters"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "quotes" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "quotes" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "quotes"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
