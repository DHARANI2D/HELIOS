-- CreateEnum
CREATE TYPE "NoticeKind" AS ENUM ('CERT_IN', 'DPDP_INTIMATION', 'DPDP_REPORT', 'DPDP_PRINCIPALS');

-- CreateEnum
CREATE TYPE "NoticeStatus" AS ENUM ('DRAFT', 'AWAITING_APPROVAL', 'APPROVED', 'SUBMITTED', 'NOT_REQUIRED');

-- CreateTable
CREATE TABLE "regulatory_notices" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "kind" "NoticeKind" NOT NULL,
    "sequence" INTEGER NOT NULL DEFAULT 1,
    "status" "NoticeStatus" NOT NULL DEFAULT 'DRAFT',
    "clockStartAt" TIMESTAMP(3) NOT NULL,
    "dueAt" TIMESTAMP(3),
    "categories" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "content" JSONB NOT NULL,
    "proposedBy" TEXT NOT NULL,
    "reasons" JSONB,
    "approvedById" TEXT,
    "approvedByName" TEXT,
    "approvedVia" TEXT,
    "approvedAt" TIMESTAMP(3),
    "submittedAt" TIMESTAMP(3),
    "submittedById" TEXT,
    "submittedVia" TEXT,
    "reference" TEXT,
    "recipientsCount" INTEGER,
    "messageId" TEXT,
    "notRequiredReason" TEXT,
    "remindedStage" INTEGER NOT NULL DEFAULT 0,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "regulatory_notices_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "regulatory_notices_tenantId_status_idx" ON "regulatory_notices"("tenantId", "status");

-- CreateIndex
CREATE INDEX "regulatory_notices_status_dueAt_idx" ON "regulatory_notices"("status", "dueAt");

-- CreateIndex
CREATE UNIQUE INDEX "regulatory_notices_caseId_kind_sequence_key" ON "regulatory_notices"("caseId", "kind", "sequence");

-- AddForeignKey
ALTER TABLE "regulatory_notices" ADD CONSTRAINT "regulatory_notices_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "regulatory_notices" ADD CONSTRAINT "regulatory_notices_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Database-enforced tenant isolation, as for the other client tables
-- (20261026070000_platform_security).
ALTER TABLE "regulatory_notices" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "regulatory_notices" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "regulatory_notices"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
