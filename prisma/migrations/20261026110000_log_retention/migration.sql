-- AlterTable
ALTER TABLE "tenants" ADD COLUMN     "logHotDays" INTEGER NOT NULL DEFAULT 90,
ADD COLUMN     "logRetentionDays" INTEGER NOT NULL DEFAULT 365;

-- CreateTable
CREATE TABLE "event_archives" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "day" TIMESTAMP(3) NOT NULL,
    "part" INTEGER NOT NULL DEFAULT 1,
    "storage" TEXT NOT NULL,
    "objectKey" TEXT NOT NULL,
    "events" INTEGER NOT NULL,
    "bytes" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "keySealed" TEXT NOT NULL,
    "firstAt" TIMESTAMP(3) NOT NULL,
    "lastAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),
    "deleteReason" TEXT,

    CONSTRAINT "event_archives_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "legal_holds" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "caseId" TEXT,
    "reason" TEXT NOT NULL,
    "fromAt" TIMESTAMP(3) NOT NULL,
    "toAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "releasedAt" TIMESTAMP(3),
    "releasedById" TEXT,
    "releaseReason" TEXT,

    CONSTRAINT "legal_holds_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "event_archives_tenantId_day_idx" ON "event_archives"("tenantId", "day");

-- CreateIndex
CREATE INDEX "event_archives_deletedAt_day_idx" ON "event_archives"("deletedAt", "day");

-- CreateIndex
CREATE INDEX "legal_holds_tenantId_idx" ON "legal_holds"("tenantId");

-- AddForeignKey
ALTER TABLE "event_archives" ADD CONSTRAINT "event_archives_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "legal_holds" ADD CONSTRAINT "legal_holds_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


ALTER TABLE "event_archives" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "event_archives" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "event_archives"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "legal_holds" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "legal_holds" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "legal_holds"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
