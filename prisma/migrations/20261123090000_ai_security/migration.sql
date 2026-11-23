-- AlterEnum
ALTER TYPE "DetectionSource" ADD VALUE 'AI_GUARD';

-- AlterTable
ALTER TABLE "security_tests" ADD COLUMN     "aiSystems" TEXT[] DEFAULT ARRAY[]::TEXT[];

-- CreateTable
CREATE TABLE "ai_systems" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "description" TEXT,
    "owner" TEXT,
    "dataClasses" TEXT[],
    "endpoint" TEXT,
    "endpointFormat" TEXT NOT NULL DEFAULT 'openai',
    "endpointModel" TEXT,
    "requestTemplate" TEXT,
    "responsePath" TEXT,
    "authHeader" TEXT,
    "authCipher" TEXT,
    "upstreamUrl" TEXT,
    "upstreamModel" TEXT,
    "upstreamCipher" TEXT,
    "privacyMode" BOOLEAN NOT NULL DEFAULT true,
    "retainContent" BOOLEAN NOT NULL DEFAULT false,
    "policy" JSONB NOT NULL,
    "policyVersion" INTEGER NOT NULL DEFAULT 1,
    "mode" TEXT NOT NULL DEFAULT 'enforce',
    "canary" TEXT NOT NULL,
    "keyHash" TEXT,
    "keyPrefix" TEXT,
    "status" TEXT NOT NULL DEFAULT 'active',
    "redTeam" JSONB,
    "redTeamAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3),
    "createdByName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_systems_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_policy_versions" (
    "id" TEXT NOT NULL,
    "systemId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "policy" JSONB NOT NULL,
    "mode" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "byName" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_policy_versions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ai_systems_keyHash_key" ON "ai_systems"("keyHash");

-- CreateIndex
CREATE INDEX "ai_systems_tenantId_idx" ON "ai_systems"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "ai_systems_tenantId_name_key" ON "ai_systems"("tenantId", "name");

-- CreateIndex
CREATE INDEX "ai_policy_versions_tenantId_idx" ON "ai_policy_versions"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "ai_policy_versions_systemId_version_key" ON "ai_policy_versions"("systemId", "version");

-- AddForeignKey
ALTER TABLE "ai_systems" ADD CONSTRAINT "ai_systems_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_policy_versions" ADD CONSTRAINT "ai_policy_versions_systemId_fkey" FOREIGN KEY ("systemId") REFERENCES "ai_systems"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- A client's own users see only that client's AI systems and their policy history.
ALTER TABLE "ai_systems" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ai_systems" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ai_systems"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "ai_policy_versions" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ai_policy_versions" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "ai_policy_versions"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
