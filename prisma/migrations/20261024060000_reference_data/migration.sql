-- AlterEnum
ALTER TYPE "ResponseActionStatus" ADD VALUE 'MANUAL_REQUIRED';

-- AlterTable
ALTER TABLE "agents" ADD COLUMN     "apiTokenHash" TEXT,
ADD COLUMN     "tokenPrefix" TEXT;

-- AlterTable
ALTER TABLE "tenants" DROP COLUMN "plan",
ADD COLUMN     "planId" TEXT;

-- DropTable
DROP TABLE "price_overrides";

-- CreateTable
CREATE TABLE "service_plans" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tagline" TEXT,
    "coverage" TEXT NOT NULL,
    "ackMinutes" JSONB NOT NULL,
    "containMinutes" JSONB NOT NULL,
    "irRetainerHours" INTEGER NOT NULL DEFAULT 0,
    "pricePerEndpoint" DOUBLE PRECISION,
    "costPerEndpoint" DOUBLE PRECISION,
    "onboardingMinimum" DOUBLE PRECISION,
    "defaultAutonomyCap" "AiAutonomy" NOT NULL DEFAULT 'CONTAIN_WITH_APPROVAL',
    "features" JSONB NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "service_plans_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "price_items" (
    "key" TEXT NOT NULL,
    "group" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "unit" TEXT NOT NULL,
    "price" DOUBLE PRECISION,
    "cost" DOUBLE PRECISION,
    "note" TEXT,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "price_items_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "volume_discounts" (
    "minEndpoints" INTEGER NOT NULL,
    "discountPct" DOUBLE PRECISION NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "volume_discounts_pkey" PRIMARY KEY ("minEndpoints")
);

-- CreateTable
CREATE TABLE "catalog_tools" (
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "controls" TEXT[],
    "actions" "PlaybookActionType"[],
    "ingest" TEXT,
    "platforms" TEXT[],
    "deployment" TEXT NOT NULL,
    "offlineCapable" BOOLEAN NOT NULL DEFAULT false,
    "priceUnit" TEXT NOT NULL,
    "listPrice" DOUBLE PRECISION,
    "priceSource" TEXT,
    "customPrice" DOUBLE PRECISION,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "catalog_tools_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "currencies" (
    "code" TEXT NOT NULL,
    "symbol" TEXT NOT NULL,
    "rate" DOUBLE PRECISION NOT NULL,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "currencies_pkey" PRIMARY KEY ("code")
);

-- CreateTable
CREATE TABLE "ai_model_prices" (
    "model" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "inputPer" DOUBLE PRECISION NOT NULL,
    "outputPer" DOUBLE PRECISION NOT NULL,
    "source" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_model_prices_pkey" PRIMARY KEY ("model")
);

-- CreateTable
CREATE TABLE "threat_feeds" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "indicatorType" "IndicatorType" NOT NULL,
    "maliciousScore" DOUBLE PRECISION NOT NULL DEFAULT 0.8,
    "description" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "lastImportedAt" TIMESTAMP(3),
    "lastCount" INTEGER,
    "lastError" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "threat_feeds_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "service_plans_key_key" ON "service_plans"("key");

-- CreateIndex
CREATE UNIQUE INDEX "threat_feeds_name_key" ON "threat_feeds"("name");

-- CreateIndex
CREATE UNIQUE INDEX "agents_apiTokenHash_key" ON "agents"("apiTokenHash");

-- AddForeignKey
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_planId_fkey" FOREIGN KEY ("planId") REFERENCES "service_plans"("id") ON DELETE SET NULL ON UPDATE CASCADE;

