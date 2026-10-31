-- CreateEnum
CREATE TYPE "ContractKind" AS ENUM ('PILOT', 'SUBSCRIPTION');

-- CreateEnum
CREATE TYPE "ContractStatus" AS ENUM ('DRAFT', 'SENT', 'ACTIVE', 'ENDED', 'TERMINATED');

-- AlterTable
ALTER TABLE "tenants" ADD COLUMN     "billingProfile" JSONB;

-- CreateTable
CREATE TABLE "contracts" (
    "id" TEXT NOT NULL,
    "reference" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "kind" "ContractKind" NOT NULL,
    "status" "ContractStatus" NOT NULL DEFAULT 'DRAFT',
    "quoteId" TEXT,
    "planName" TEXT,
    "currency" TEXT NOT NULL,
    "monthlyFee" INTEGER NOT NULL DEFAULT 0,
    "endpointsCommitted" INTEGER NOT NULL DEFAULT 0,
    "overagePerEndpoint" INTEGER NOT NULL DEFAULT 0,
    "oneTimeFee" INTEGER NOT NULL DEFAULT 0,
    "billingCycle" TEXT NOT NULL DEFAULT 'monthly',
    "paymentTermsDays" INTEGER NOT NULL DEFAULT 30,
    "startsAt" TIMESTAMP(3) NOT NULL,
    "endsAt" TIMESTAMP(3) NOT NULL,
    "autoRenew" BOOLEAN NOT NULL DEFAULT false,
    "noticeDays" INTEGER NOT NULL DEFAULT 30,
    "liabilityCapMonths" INTEGER NOT NULL DEFAULT 12,
    "autonomyCap" "AiAutonomy",
    "rulebookVersion" INTEGER,
    "dpaReference" TEXT,
    "terms" TEXT,
    "successCriteria" JSONB,
    "pilotOutcome" TEXT,
    "convertedToId" TEXT,
    "billedThrough" TIMESTAMP(3),
    "sentAt" TIMESTAMP(3),
    "signedAt" TIMESTAMP(3),
    "signedByName" TEXT,
    "signedByTitle" TEXT,
    "signedVia" TEXT,
    "signedRecordedById" TEXT,
    "endedAt" TIMESTAMP(3),
    "endReason" TEXT,
    "remindedAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "contracts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "invoices" (
    "id" TEXT NOT NULL,
    "number" TEXT,
    "tenantId" TEXT NOT NULL,
    "contractId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "currency" TEXT NOT NULL,
    "periodFrom" TIMESTAMP(3) NOT NULL,
    "periodTo" TIMESTAMP(3) NOT NULL,
    "lines" JSONB NOT NULL,
    "subtotal" INTEGER NOT NULL,
    "taxMode" TEXT,
    "taxLines" JSONB,
    "total" INTEGER NOT NULL,
    "supplier" JSONB,
    "recipient" JSONB,
    "sac" TEXT,
    "issuedAt" TIMESTAMP(3),
    "dueAt" TIMESTAMP(3),
    "paidAt" TIMESTAMP(3),
    "paymentRef" TEXT,
    "voidedAt" TIMESTAMP(3),
    "voidReason" TEXT,
    "remindedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "invoices_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "contracts_reference_key" ON "contracts"("reference");

-- CreateIndex
CREATE INDEX "contracts_tenantId_idx" ON "contracts"("tenantId");

-- CreateIndex
CREATE INDEX "contracts_status_endsAt_idx" ON "contracts"("status", "endsAt");

-- CreateIndex
CREATE UNIQUE INDEX "invoices_number_key" ON "invoices"("number");

-- CreateIndex
CREATE INDEX "invoices_tenantId_idx" ON "invoices"("tenantId");

-- CreateIndex
CREATE INDEX "invoices_status_dueAt_idx" ON "invoices"("status", "dueAt");

-- CreateIndex
CREATE UNIQUE INDEX "invoices_contractId_periodFrom_key" ON "invoices"("contractId", "periodFrom");

-- AddForeignKey
ALTER TABLE "contracts" ADD CONSTRAINT "contracts_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "invoices" ADD CONSTRAINT "invoices_contractId_fkey" FOREIGN KEY ("contractId") REFERENCES "contracts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


ALTER TABLE "contracts" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "contracts" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "contracts"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "invoices" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "invoices" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "invoices"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
