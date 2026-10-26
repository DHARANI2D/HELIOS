-- CreateEnum
CREATE TYPE "DetectionRuleStatus" AS ENUM ('TESTING', 'ACTIVE', 'DISABLED');

-- AlterEnum
ALTER TYPE "DetectionSource" ADD VALUE 'SIGMA_RULE';

-- CreateTable
CREATE TABLE "detection_rules" (
    "id" TEXT NOT NULL,
    "sigmaId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "level" TEXT NOT NULL,
    "status" "DetectionRuleStatus" NOT NULL DEFAULT 'TESTING',
    "tenantId" TEXT,
    "yaml" TEXT NOT NULL,
    "techniques" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "tactics" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "logsource" TEXT NOT NULL,
    "warnings" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "testHits" INTEGER NOT NULL DEFAULT 0,
    "lastHitAt" TIMESTAMP(3),
    "samples" JSONB,
    "createdById" TEXT,
    "updatedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "detection_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detection_tunings" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "field" TEXT,
    "op" TEXT,
    "value" TEXT,
    "severity" "CaseSeverity",
    "reason" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "hits" INTEGER NOT NULL DEFAULT 0,
    "lastHitAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "detection_tunings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "detection_rules_status_idx" ON "detection_rules"("status");

-- CreateIndex
CREATE INDEX "detection_rules_sigmaId_idx" ON "detection_rules"("sigmaId");

-- CreateIndex
CREATE INDEX "detection_tunings_tenantId_idx" ON "detection_tunings"("tenantId");

-- AddForeignKey
ALTER TABLE "detection_tunings" ADD CONSTRAINT "detection_tunings_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Client-scoped sessions see only their own client's tuning and rules (a
-- rule for every client has no tenantId and stays out of their sight).
ALTER TABLE "detection_tunings" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "detection_tunings" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "detection_tunings"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
ALTER TABLE "detection_rules" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "detection_rules" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "detection_rules"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
