-- MSSP multi-tenancy pivot: Organization model, role redesign
-- (ANALYST/ADMIN -> PLATFORM_OWNER/PLATFORM_ANALYST/ORG_ADMIN/ORG_ANALYST/
-- ORG_VIEWER), org-scoping FKs on Case/Agent/IngestedEvent/Playbook/
-- AuditLog, and the new service-catalog/billing/pentest/integration
-- models. Hand-written (like 20260922162227_audit_log_seq_ordering)
-- because `prisma migrate dev` refuses to run non-interactively and this
-- changes an enum with existing rows.

-- ---------------------------------------------------------------------
-- New enums used by models below
-- ---------------------------------------------------------------------
CREATE TYPE "OrganizationStatus" AS ENUM ('TRIAL', 'ACTIVE', 'SUSPENDED');
CREATE TYPE "AiTier" AS ENUM ('ESSENTIAL', 'PROFESSIONAL', 'ENTERPRISE', 'SELF_HOSTED');
CREATE TYPE "ServiceType" AS ENUM ('ENDPOINT_SECURITY', 'CLOUD_SECURITY', 'NETWORK_SECURITY', 'EMAIL_SECURITY', 'AGENT_GOVERNANCE', 'PENETRATION_TESTING');
CREATE TYPE "SubscriptionStatus" AS ENUM ('TRIAL', 'ACTIVE', 'PAST_DUE', 'CANCELED');
CREATE TYPE "InvoiceStatus" AS ENUM ('DRAFT', 'SENT', 'PAID', 'OVERDUE', 'VOID');
CREATE TYPE "PentestRequestStatus" AS ENUM ('REQUESTED', 'SCHEDULED', 'IN_PROGRESS', 'COMPLETED', 'CANCELED');
CREATE TYPE "IntegrationCategory" AS ENUM ('SIEM', 'EDR', 'CLOUD', 'IDENTITY', 'EMAIL', 'OTHER');
CREATE TYPE "IntegrationStatus" AS ENUM ('CONNECTED', 'ERROR', 'DISCONNECTED');

-- CaseSource gains PENETRATION_TEST (additive, safe outside the same
-- transaction that would consume it — nothing in this migration inserts
-- that value).
ALTER TYPE "CaseSource" ADD VALUE 'PENETRATION_TEST';

-- ---------------------------------------------------------------------
-- Organization table (create before anything references it)
-- ---------------------------------------------------------------------
CREATE TABLE "organizations" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "status" "OrganizationStatus" NOT NULL DEFAULT 'TRIAL',
    "aiTier" "AiTier" NOT NULL DEFAULT 'ESSENTIAL',
    "selfHostedOllamaUrl" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "organizations_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "organizations_slug_key" ON "organizations"("slug");

-- ---------------------------------------------------------------------
-- UserRole enum redesign + backfill existing rows
-- ---------------------------------------------------------------------
CREATE TYPE "UserRole_new" AS ENUM ('PLATFORM_OWNER', 'PLATFORM_ANALYST', 'ORG_ADMIN', 'ORG_ANALYST', 'ORG_VIEWER');

ALTER TABLE "users" ALTER COLUMN "role" DROP DEFAULT;
ALTER TABLE "users" ALTER COLUMN "role" TYPE TEXT USING "role"::TEXT;
UPDATE "users" SET "role" = CASE "role"
    WHEN 'ADMIN' THEN 'PLATFORM_OWNER'
    WHEN 'ANALYST' THEN 'PLATFORM_ANALYST'
    ELSE 'ORG_VIEWER'
END;
ALTER TABLE "users" ALTER COLUMN "role" TYPE "UserRole_new" USING ("role"::"UserRole_new");
ALTER TABLE "users" ALTER COLUMN "role" SET DEFAULT 'ORG_VIEWER';
DROP TYPE "UserRole";
ALTER TYPE "UserRole_new" RENAME TO "UserRole";

-- ---------------------------------------------------------------------
-- Org-scoping FK on users + the other existing tables
-- ---------------------------------------------------------------------
ALTER TABLE "users" ADD COLUMN "organizationId" TEXT;
CREATE INDEX "users_organizationId_idx" ON "users"("organizationId");
ALTER TABLE "users" ADD CONSTRAINT "users_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "cases" ADD COLUMN "organizationId" TEXT;
CREATE INDEX "cases_organizationId_idx" ON "cases"("organizationId");
ALTER TABLE "cases" ADD CONSTRAINT "cases_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ingested_events" ADD COLUMN "organizationId" TEXT;
CREATE INDEX "ingested_events_organizationId_idx" ON "ingested_events"("organizationId");
ALTER TABLE "ingested_events" ADD CONSTRAINT "ingested_events_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "playbooks" ADD COLUMN "organizationId" TEXT;
CREATE INDEX "playbooks_organizationId_idx" ON "playbooks"("organizationId");
ALTER TABLE "playbooks" ADD CONSTRAINT "playbooks_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "audit_logs" ADD COLUMN "organizationId" TEXT;
CREATE INDEX "audit_logs_organizationId_idx" ON "audit_logs"("organizationId");
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- agents: name goes from globally-unique to unique-per-org
ALTER TABLE "agents" ADD COLUMN "organizationId" TEXT;
DROP INDEX "agents_name_key";
CREATE INDEX "agents_organizationId_idx" ON "agents"("organizationId");
CREATE UNIQUE INDEX "agents_organizationId_name_key" ON "agents"("organizationId", "name");
ALTER TABLE "agents" ADD CONSTRAINT "agents_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------------------------------------------------------------------
-- Service catalog + billing
-- ---------------------------------------------------------------------
CREATE TABLE "plans" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "serviceType" "ServiceType" NOT NULL,
    "aiTier" "AiTier" NOT NULL,
    "priceMonthly" DECIMAL(10,2) NOT NULL,
    "includedUnits" JSONB,
    "description" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "plans_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "subscriptions" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "planId" TEXT NOT NULL,
    "status" "SubscriptionStatus" NOT NULL DEFAULT 'ACTIVE',
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "currentPeriodEnd" TIMESTAMP(3) NOT NULL,
    "canceledAt" TIMESTAMP(3),

    CONSTRAINT "subscriptions_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "subscriptions_organizationId_idx" ON "subscriptions"("organizationId");
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_planId_fkey" FOREIGN KEY ("planId") REFERENCES "plans"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "invoices" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "number" TEXT NOT NULL,
    "issueDate" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "dueDate" TIMESTAMP(3) NOT NULL,
    "status" "InvoiceStatus" NOT NULL DEFAULT 'DRAFT',
    "currency" TEXT NOT NULL DEFAULT 'USD',
    "totalAmount" DECIMAL(10,2) NOT NULL,
    "paidAt" TIMESTAMP(3),
    "notes" TEXT,

    CONSTRAINT "invoices_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "invoices_number_key" ON "invoices"("number");
CREATE INDEX "invoices_organizationId_idx" ON "invoices"("organizationId");
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "invoice_line_items" (
    "id" TEXT NOT NULL,
    "invoiceId" TEXT NOT NULL,
    "subscriptionId" TEXT,
    "description" TEXT NOT NULL,
    "quantity" INTEGER NOT NULL DEFAULT 1,
    "unitPrice" DECIMAL(10,2) NOT NULL,
    "amount" DECIMAL(10,2) NOT NULL,

    CONSTRAINT "invoice_line_items_pkey" PRIMARY KEY ("id")
);
ALTER TABLE "invoice_line_items" ADD CONSTRAINT "invoice_line_items_invoiceId_fkey" FOREIGN KEY ("invoiceId") REFERENCES "invoices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "invoice_line_items" ADD CONSTRAINT "invoice_line_items_subscriptionId_fkey" FOREIGN KEY ("subscriptionId") REFERENCES "subscriptions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------------------------------------------------------------------
-- Pentest-as-a-service
-- ---------------------------------------------------------------------
CREATE TABLE "pentest_requests" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "requestedById" TEXT NOT NULL,
    "scope" JSONB NOT NULL,
    "status" "PentestRequestStatus" NOT NULL DEFAULT 'REQUESTED',
    "scheduledAt" TIMESTAMP(3),
    "assignedToId" TEXT,
    "reportCaseId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "pentest_requests_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "pentest_requests_reportCaseId_key" ON "pentest_requests"("reportCaseId");
CREATE INDEX "pentest_requests_organizationId_idx" ON "pentest_requests"("organizationId");
ALTER TABLE "pentest_requests" ADD CONSTRAINT "pentest_requests_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "pentest_requests" ADD CONSTRAINT "pentest_requests_requestedById_fkey" FOREIGN KEY ("requestedById") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "pentest_requests" ADD CONSTRAINT "pentest_requests_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "pentest_requests" ADD CONSTRAINT "pentest_requests_reportCaseId_fkey" FOREIGN KEY ("reportCaseId") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- ---------------------------------------------------------------------
-- Integrations (webhook ingestion framework)
-- ---------------------------------------------------------------------
CREATE TABLE "integrations" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "vendorLabel" TEXT NOT NULL,
    "category" "IntegrationCategory" NOT NULL,
    "status" "IntegrationStatus" NOT NULL DEFAULT 'DISCONNECTED',
    "webhookSecret" TEXT NOT NULL,
    "lastIngestAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "integrations_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "integrations_organizationId_idx" ON "integrations"("organizationId");
ALTER TABLE "integrations" ADD CONSTRAINT "integrations_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
