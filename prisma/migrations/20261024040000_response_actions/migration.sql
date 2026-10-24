-- CreateEnum
CREATE TYPE "ResponseActionStatus" AS ENUM ('SUGGESTED', 'PENDING_APPROVAL', 'EXECUTED', 'REJECTED', 'FAILED', 'BLOCKED', 'ROLLED_BACK');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "PlaybookActionType" ADD VALUE 'RELEASE_HOST';
ALTER TYPE "PlaybookActionType" ADD VALUE 'UNBLOCK_IP';
ALTER TYPE "PlaybookActionType" ADD VALUE 'ENABLE_USER';

-- AlterTable
ALTER TABLE "ai_agent_profiles" ADD COLUMN     "effort" TEXT NOT NULL DEFAULT 'medium';

-- CreateTable
CREATE TABLE "response_actions" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "tenantId" TEXT,
    "actionType" "PlaybookActionType" NOT NULL,
    "target" TEXT,
    "parameters" JSONB,
    "source" TEXT NOT NULL,
    "status" "ResponseActionStatus" NOT NULL,
    "rationale" TEXT,
    "confidence" DOUBLE PRECISION,
    "policyReason" TEXT,
    "aiRunId" TEXT,
    "requestedById" TEXT,
    "decidedById" TEXT,
    "decidedAt" TIMESTAMP(3),
    "result" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "response_actions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "response_actions_status_createdAt_idx" ON "response_actions"("status", "createdAt");

-- CreateIndex
CREATE INDEX "response_actions_caseId_idx" ON "response_actions"("caseId");

-- AddForeignKey
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "response_actions" ADD CONSTRAINT "response_actions_aiRunId_fkey" FOREIGN KEY ("aiRunId") REFERENCES "ai_runs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

