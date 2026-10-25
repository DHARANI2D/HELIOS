-- Inventory rows can say what they are beyond a computer: a firewall, a
-- PLC, a cloud VM. Null keeps placing hosts by their operating system.
ALTER TABLE "endpoints" ADD COLUMN "assetClass" TEXT;
ALTER TABLE "endpoints" ADD COLUMN "assetType" TEXT;

-- CreateIndex
CREATE INDEX "endpoints_tenantId_assetClass_idx" ON "endpoints"("tenantId", "assetClass");
