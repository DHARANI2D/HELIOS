-- Client rulebooks: versioned, signed rules for what HELIOS may do on a
-- client's estate, an allowlist with owners and expiry, and on every
-- response action the rulebook version, decision trace and approvals.

-- CreateEnum
CREATE TYPE "OrgPolicyStatus" AS ENUM ('DRAFT', 'AWAITING_SIGNATURE', 'ACTIVE', 'SUPERSEDED');

-- AlterTable
ALTER TABLE "response_actions" ADD COLUMN     "approvals" JSONB,
ADD COLUMN     "policyHash" TEXT,
ADD COLUMN     "policyVersion" INTEGER,
ADD COLUMN     "requiredApprovals" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "trace" JSONB;

-- CreateTable
CREATE TABLE "org_policies" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "status" "OrgPolicyStatus" NOT NULL DEFAULT 'DRAFT',
    "body" JSONB NOT NULL,
    "contentHash" TEXT NOT NULL,
    "template" TEXT,
    "reason" TEXT,
    "authoredById" TEXT,
    "authoredByName" TEXT NOT NULL,
    "submittedAt" TIMESTAMP(3),
    "signedById" TEXT,
    "signedByName" TEXT,
    "signedAt" TIMESTAMP(3),
    "signatureNote" TEXT,
    "effectiveFrom" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "org_policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policy_allowlist" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policy_allowlist_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "org_policies_tenantId_status_idx" ON "org_policies"("tenantId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "org_policies_tenantId_version_key" ON "org_policies"("tenantId", "version");

-- CreateIndex
CREATE INDEX "policy_allowlist_tenantId_kind_value_idx" ON "policy_allowlist"("tenantId", "kind", "value");

-- AddForeignKey
ALTER TABLE "org_policies" ADD CONSTRAINT "org_policies_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policy_allowlist" ADD CONSTRAINT "policy_allowlist_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

