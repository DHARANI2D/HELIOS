-- Change control for containment rules (lib/changes).

-- CreateEnum
CREATE TYPE "RuleChangeKind" AS ENUM ('RULEBOOK_VERSION', 'ALLOWLIST_ADD', 'ALLOWLIST_REMOVE', 'AUTONOMY_RAISE', 'AI_CONSENT', 'AGENT_PROFILE', 'AI_SETTINGS');

-- CreateEnum
CREATE TYPE "RuleChangeStatus" AS ENUM ('PENDING', 'APPLIED', 'REJECTED', 'WITHDRAWN', 'STALE');

-- AlterTable
ALTER TABLE "org_policies" ADD COLUMN     "heliosApprovedAt" TIMESTAMP(3),
ADD COLUMN     "heliosApprovedById" TEXT,
ADD COLUMN     "heliosApprovedByName" TEXT;

-- CreateTable
CREATE TABLE "rule_changes" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "kind" "RuleChangeKind" NOT NULL,
    "status" "RuleChangeStatus" NOT NULL DEFAULT 'PENDING',
    "summary" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "payloadHash" TEXT NOT NULL,
    "requestedById" TEXT,
    "requestedByName" TEXT NOT NULL,
    "requestedByClient" BOOLEAN NOT NULL DEFAULT false,
    "clientApprovedById" TEXT,
    "clientApprovedByName" TEXT,
    "clientApprovedAt" TIMESTAMP(3),
    "clientOnBehalf" BOOLEAN NOT NULL DEFAULT false,
    "clientApprovalNote" TEXT,
    "heliosApprovedById" TEXT,
    "heliosApprovedByName" TEXT,
    "heliosApprovedAt" TIMESTAMP(3),
    "heliosApprovalNote" TEXT,
    "decidedById" TEXT,
    "decidedByName" TEXT,
    "decidedAt" TIMESTAMP(3),
    "decisionNote" TEXT,
    "appliedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "rule_changes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "rule_changes_tenantId_status_idx" ON "rule_changes"("tenantId", "status");

-- CreateIndex
CREATE INDEX "rule_changes_status_createdAt_idx" ON "rule_changes"("status", "createdAt");

-- AddForeignKey
ALTER TABLE "rule_changes" ADD CONSTRAINT "rule_changes_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- A client's own users see only that client's changes; platform changes
-- (no client) are never visible to them.
ALTER TABLE "rule_changes" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rule_changes" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "rule_changes"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
