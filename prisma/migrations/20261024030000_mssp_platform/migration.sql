-- CreateEnum
CREATE TYPE "SecurityDomain" AS ENUM ('ENDPOINT', 'NETWORK', 'EMAIL', 'IDENTITY', 'CLOUD', 'AI_AGENTS');

-- CreateEnum
CREATE TYPE "TenantStatus" AS ENUM ('ONBOARDING', 'ACTIVE', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "IntegrationStatus" AS ENUM ('PENDING', 'CONNECTED', 'DEGRADED', 'DISCONNECTED');

-- CreateEnum
CREATE TYPE "AiAutonomy" AS ENUM ('OFF', 'SUGGEST', 'CONTAIN_WITH_APPROVAL', 'AUTO_CONTAIN');

-- CreateEnum
CREATE TYPE "QuoteStatus" AS ENUM ('DRAFT', 'SENT', 'ACCEPTED', 'LOST');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "PlaybookActionType" ADD VALUE 'DISABLE_USER';
ALTER TYPE "PlaybookActionType" ADD VALUE 'QUARANTINE_FILE';
ALTER TYPE "PlaybookActionType" ADD VALUE 'BLOCK_SENDER';

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.


ALTER TYPE "UserRole" ADD VALUE 'SOC_MANAGER';
ALTER TYPE "UserRole" ADD VALUE 'TRIAGE_ANALYST';
ALTER TYPE "UserRole" ADD VALUE 'INCIDENT_RESPONDER';
ALTER TYPE "UserRole" ADD VALUE 'THREAT_HUNTER';
ALTER TYPE "UserRole" ADD VALUE 'DETECTION_ENGINEER';
ALTER TYPE "UserRole" ADD VALUE 'AUDITOR';
ALTER TYPE "UserRole" ADD VALUE 'SALES';
ALTER TYPE "UserRole" ADD VALUE 'CLIENT_ADMIN';
ALTER TYPE "UserRole" ADD VALUE 'CLIENT_VIEWER';

-- AlterTable
ALTER TABLE "agents" ADD COLUMN     "tenantId" TEXT;

-- AlterTable
ALTER TABLE "cases" ADD COLUMN     "acknowledgedAt" TIMESTAMP(3),
ADD COLUMN     "aiStatus" TEXT,
ADD COLUMN     "containedAt" TIMESTAMP(3),
ADD COLUMN     "domain" "SecurityDomain",
ADD COLUMN     "slaDueAt" TIMESTAMP(3),
ADD COLUMN     "tenantId" TEXT,
ADD COLUMN     "tier" INTEGER NOT NULL DEFAULT 1;

-- AlterTable
ALTER TABLE "security_events" ADD COLUMN     "integrationId" TEXT,
ADD COLUMN     "tenantId" TEXT;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "active" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "domains" "SecurityDomain"[] DEFAULT ARRAY[]::"SecurityDomain"[],
ADD COLUMN     "failedLogins" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "lastLoginAt" TIMESTAMP(3),
ADD COLUMN     "lockedUntil" TIMESTAMP(3),
ADD COLUMN     "preferences" JSONB,
ADD COLUMN     "tenantId" TEXT,
ADD COLUMN     "title" TEXT;

-- CreateTable
CREATE TABLE "tenants" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "industry" TEXT,
    "status" "TenantStatus" NOT NULL DEFAULT 'ONBOARDING',
    "plan" TEXT NOT NULL DEFAULT 'professional',
    "contactName" TEXT,
    "contactEmail" TEXT,
    "endpointsLicensed" INTEGER NOT NULL DEFAULT 0,
    "usersLicensed" INTEGER NOT NULL DEFAULT 0,
    "aiAutonomyCap" "AiAutonomy" NOT NULL DEFAULT 'CONTAIN_WITH_APPROVAL',
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_comments" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "authorId" TEXT,
    "authorName" TEXT NOT NULL,
    "kind" TEXT NOT NULL DEFAULT 'comment',
    "body" TEXT NOT NULL,
    "internal" BOOLEAN NOT NULL DEFAULT true,
    "mentions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "case_comments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_watchers" (
    "caseId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "case_watchers_pkey" PRIMARY KEY ("caseId","userId")
);

-- CreateTable
CREATE TABLE "notifications" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT,
    "href" TEXT,
    "caseId" TEXT,
    "actorName" TEXT,
    "readAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notifications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "integrations" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "vendor" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" "IntegrationStatus" NOT NULL DEFAULT 'PENDING',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "config" JSONB,
    "secretCipher" TEXT,
    "ingestTokenHash" TEXT,
    "tokenPrefix" TEXT,
    "allowedRoles" "UserRole"[] DEFAULT ARRAY[]::"UserRole"[],
    "createdById" TEXT,
    "lastEventAt" TIMESTAMP(3),
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "integration_assignments" (
    "integrationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "integration_assignments_pkey" PRIMARY KEY ("integrationId","userId")
);

-- CreateTable
CREATE TABLE "endpoints" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "hostname" TEXT NOT NULL,
    "os" TEXT,
    "ipAddress" TEXT,
    "owner" TEXT,
    "criticality" TEXT NOT NULL DEFAULT 'standard',
    "protections" JSONB,
    "isolated" BOOLEAN NOT NULL DEFAULT false,
    "isolatedAt" TIMESTAMP(3),
    "isolatedBy" TEXT,
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "lastSeenAt" TIMESTAMP(3),
    "source" TEXT NOT NULL DEFAULT 'telemetry',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "endpoints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_providers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "baseUrl" TEXT,
    "model" TEXT NOT NULL,
    "apiKeyCipher" TEXT,
    "isLocal" BOOLEAN NOT NULL DEFAULT false,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "lastCheckedAt" TIMESTAMP(3),
    "lastCheckOk" BOOLEAN,
    "lastCheckMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_agent_profiles" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "providerId" TEXT,
    "model" TEXT,
    "autonomy" "AiAutonomy" NOT NULL DEFAULT 'SUGGEST',
    "allowedActions" "PlaybookActionType"[] DEFAULT ARRAY[]::"PlaybookActionType"[],
    "minConfidence" DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    "instructions" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_agent_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_runs" (
    "id" TEXT NOT NULL,
    "caseId" TEXT,
    "agentKey" TEXT NOT NULL,
    "trigger" TEXT NOT NULL,
    "engine" TEXT NOT NULL,
    "model" TEXT,
    "isLocal" BOOLEAN NOT NULL DEFAULT false,
    "status" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION,
    "output" JSONB,
    "grounding" JSONB,
    "error" TEXT,
    "durationMs" INTEGER,
    "inputTokens" INTEGER,
    "outputTokens" INTEGER,
    "requestedById" TEXT,
    "feedback" TEXT,
    "feedbackNote" TEXT,
    "feedbackById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "platform_settings" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "platform_settings_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "quotes" (
    "id" TEXT NOT NULL,
    "reference" TEXT NOT NULL,
    "clientName" TEXT NOT NULL,
    "tenantId" TEXT,
    "status" "QuoteStatus" NOT NULL DEFAULT 'DRAFT',
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "config" JSONB NOT NULL,
    "totals" JSONB NOT NULL,
    "notes" TEXT,
    "validUntil" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "quotes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "price_overrides" (
    "itemKey" TEXT NOT NULL,
    "unitPrice" DOUBLE PRECISION NOT NULL,
    "unitCost" DOUBLE PRECISION,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "price_overrides_pkey" PRIMARY KEY ("itemKey")
);

-- CreateIndex
CREATE UNIQUE INDEX "tenants_name_key" ON "tenants"("name");

-- CreateIndex
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants"("slug");

-- CreateIndex
CREATE INDEX "case_comments_caseId_createdAt_idx" ON "case_comments"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "notifications_userId_readAt_createdAt_idx" ON "notifications"("userId", "readAt", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "integrations_ingestTokenHash_key" ON "integrations"("ingestTokenHash");

-- CreateIndex
CREATE INDEX "integrations_tenantId_category_idx" ON "integrations"("tenantId", "category");

-- CreateIndex
CREATE INDEX "endpoints_tenantId_hostname_idx" ON "endpoints"("tenantId", "hostname");

-- CreateIndex
CREATE INDEX "endpoints_hostname_idx" ON "endpoints"("hostname");

-- CreateIndex
CREATE UNIQUE INDEX "ai_providers_name_key" ON "ai_providers"("name");

-- CreateIndex
CREATE UNIQUE INDEX "ai_agent_profiles_key_key" ON "ai_agent_profiles"("key");

-- CreateIndex
CREATE INDEX "ai_runs_caseId_createdAt_idx" ON "ai_runs"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "ai_runs_createdAt_idx" ON "ai_runs"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "quotes_reference_key" ON "quotes"("reference");

-- CreateIndex
CREATE INDEX "quotes_createdAt_idx" ON "quotes"("createdAt");

-- CreateIndex
CREATE INDEX "cases_tenantId_status_idx" ON "cases"("tenantId", "status");

-- CreateIndex
CREATE INDEX "cases_domain_status_idx" ON "cases"("domain", "status");

-- CreateIndex
CREATE INDEX "security_events_tenantId_timestamp_idx" ON "security_events"("tenantId", "timestamp");

-- CreateIndex
CREATE INDEX "users_tenantId_idx" ON "users"("tenantId");

-- AddForeignKey
ALTER TABLE "users" ADD CONSTRAINT "users_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cases" ADD CONSTRAINT "cases_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_comments" ADD CONSTRAINT "case_comments_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_comments" ADD CONSTRAINT "case_comments_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_watchers" ADD CONSTRAINT "case_watchers_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_watchers" ADD CONSTRAINT "case_watchers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notifications" ADD CONSTRAINT "notifications_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integrations" ADD CONSTRAINT "integrations_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integration_assignments" ADD CONSTRAINT "integration_assignments_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integration_assignments" ADD CONSTRAINT "integration_assignments_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "endpoints" ADD CONSTRAINT "endpoints_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_agent_profiles" ADD CONSTRAINT "ai_agent_profiles_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "ai_providers"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_runs" ADD CONSTRAINT "ai_runs_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_runs" ADD CONSTRAINT "ai_runs_feedbackById_fkey" FOREIGN KEY ("feedbackById") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "quotes" ADD CONSTRAINT "quotes_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "quotes" ADD CONSTRAINT "quotes_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;


-- Backfill analyst queues for existing cases. SIEM cases take the dominant
-- telemetry source of their linked events.
UPDATE "cases" c SET "domain" = CASE c."sourceType"
  WHEN 'EMAIL_ANALYSIS' THEN 'EMAIL'::"SecurityDomain"
  WHEN 'AGENT_GOVERNANCE' THEN 'AI_AGENTS'::"SecurityDomain"
  WHEN 'SOC_INVESTIGATION' THEN 'ENDPOINT'::"SecurityDomain"
  ELSE COALESCE((
    SELECT (CASE e."source" WHEN 'auth' THEN 'IDENTITY' WHEN 'network' THEN 'NETWORK' WHEN 'cloud' THEN 'CLOUD' ELSE 'ENDPOINT' END)::"SecurityDomain"
    FROM "security_events" e WHERE e."caseId" = c."id"
    GROUP BY e."source" ORDER BY count(*) DESC LIMIT 1
  ), 'ENDPOINT'::"SecurityDomain")
END
WHERE c."domain" IS NULL;
