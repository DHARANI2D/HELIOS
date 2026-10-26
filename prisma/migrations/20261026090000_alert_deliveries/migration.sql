-- CreateEnum
CREATE TYPE "AlertDeliveryStatus" AS ENUM ('PENDING', 'SENT', 'FAILED', 'SKIPPED');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "alertPrefs" JSONB,
ADD COLUMN     "phone" TEXT;

-- CreateTable
CREATE TABLE "alert_deliveries" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "tenantId" TEXT,
    "channel" TEXT NOT NULL,
    "to" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "href" TEXT,
    "caseId" TEXT,
    "status" "AlertDeliveryStatus" NOT NULL DEFAULT 'PENDING',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastError" TEXT,
    "providerRef" TEXT,
    "sentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alert_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "alert_deliveries_status_nextAttemptAt_idx" ON "alert_deliveries"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "alert_deliveries_userId_createdAt_idx" ON "alert_deliveries"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "alert_deliveries_to_createdAt_idx" ON "alert_deliveries"("to", "createdAt");

-- AddForeignKey
ALTER TABLE "alert_deliveries" ADD CONSTRAINT "alert_deliveries_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;


-- Client-scoped sessions see only their own client's deliveries.
ALTER TABLE "alert_deliveries" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "alert_deliveries" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "alert_deliveries"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
