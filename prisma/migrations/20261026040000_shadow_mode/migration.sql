-- Shadow mode: analysts' dispositions on close, silent AI proposals, a
-- per-client autonomy ladder per action type, and AI decisions scored
-- against what analysts did.

-- CreateEnum
CREATE TYPE "CaseDisposition" AS ENUM ('TRUE_POSITIVE', 'BENIGN_TRUE_POSITIVE', 'FALSE_POSITIVE');

-- AlterEnum
ALTER TYPE "ResponseActionStatus" ADD VALUE 'SHADOW';

-- AlterTable
ALTER TABLE "cases" ADD COLUMN     "disposition" "CaseDisposition",
ADD COLUMN     "dispositionAt" TIMESTAMP(3),
ADD COLUMN     "dispositionById" TEXT,
ADD COLUMN     "dispositionReason" TEXT;

-- CreateTable
CREATE TABLE "autonomy_levels" (
    "tenantId" TEXT NOT NULL,
    "actionType" "PlaybookActionType" NOT NULL,
    "level" INTEGER NOT NULL,
    "reason" TEXT,
    "changedByName" TEXT NOT NULL,
    "proposedLevel" INTEGER,
    "proposedAt" TIMESTAMP(3),
    "proposalStats" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "autonomy_levels_pkey" PRIMARY KEY ("tenantId","actionType")
);

-- CreateTable
CREATE TABLE "ai_decision_outcomes" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "caseId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "actionType" "PlaybookActionType",
    "target" TEXT,
    "level" INTEGER,
    "aiOutcome" TEXT NOT NULL,
    "humanOutcome" TEXT NOT NULL,
    "agreed" BOOLEAN NOT NULL,
    "falseContainment" BOOLEAN NOT NULL DEFAULT false,
    "critical" BOOLEAN NOT NULL DEFAULT false,
    "severity" "CaseSeverity" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_decision_outcomes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ai_decision_outcomes_tenantId_actionType_createdAt_idx" ON "ai_decision_outcomes"("tenantId", "actionType", "createdAt");

-- CreateIndex
CREATE INDEX "ai_decision_outcomes_caseId_idx" ON "ai_decision_outcomes"("caseId");

-- AddForeignKey
ALTER TABLE "autonomy_levels" ADD CONSTRAINT "autonomy_levels_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_decision_outcomes" ADD CONSTRAINT "ai_decision_outcomes_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

