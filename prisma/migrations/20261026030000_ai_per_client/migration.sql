-- AI per client: a client's own providers (bring your own key) and their
-- region, a per-client AI policy and budget, model evaluation scores, and
-- on every AI run the client and why that model ran it.

-- AlterTable
ALTER TABLE "ai_providers" ADD COLUMN     "region" TEXT,
ADD COLUMN     "tenantId" TEXT;

-- AlterTable
ALTER TABLE "ai_runs" ADD COLUMN     "resolution" JSONB,
ADD COLUMN     "tenantId" TEXT;

-- CreateTable
CREATE TABLE "tenant_ai_policies" (
    "tenantId" TEXT NOT NULL,
    "defaults" JSONB,
    "monthlyBudgetUsd" DOUBLE PRECISION,
    "budgetAlertMonth" TEXT,
    "budgetReachedMonth" TEXT,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_ai_policies_pkey" PRIMARY KEY ("tenantId")
);

-- CreateTable
CREATE TABLE "model_capabilities" (
    "id" TEXT NOT NULL,
    "model" TEXT NOT NULL,
    "agentKey" TEXT NOT NULL,
    "score" DOUBLE PRECISION NOT NULL,
    "passed" BOOLEAN NOT NULL,
    "cases" INTEGER NOT NULL,
    "details" JSONB,
    "evaluatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "model_capabilities_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "model_capabilities_model_agentKey_key" ON "model_capabilities"("model", "agentKey");

-- CreateIndex
CREATE INDEX "ai_providers_tenantId_idx" ON "ai_providers"("tenantId");

-- CreateIndex
CREATE INDEX "ai_runs_tenantId_createdAt_idx" ON "ai_runs"("tenantId", "createdAt");

-- AddForeignKey
ALTER TABLE "tenant_ai_policies" ADD CONSTRAINT "tenant_ai_policies_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_providers" ADD CONSTRAINT "ai_providers_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Existing runs belong to their case's client.
UPDATE "ai_runs" r SET "tenantId" = c."tenantId" FROM "cases" c WHERE r."caseId" = c."id";
