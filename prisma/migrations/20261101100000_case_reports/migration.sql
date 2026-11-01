-- Final analyses written by the autonomous pipeline (lib/ai/autopilot.ts).

-- AlterTable
ALTER TABLE "cases" ADD COLUMN     "analysisStatus" TEXT,
ADD COLUMN     "analysisUpdatedAt" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "case_reports" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "tenantId" TEXT,
    "version" INTEGER NOT NULL DEFAULT 1,
    "status" TEXT NOT NULL DEFAULT 'ready',
    "verdict" TEXT,
    "confidence" DOUBLE PRECISION,
    "summary" TEXT NOT NULL,
    "body" JSONB NOT NULL,
    "engine" TEXT NOT NULL,
    "model" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewedById" TEXT,
    "reviewedByName" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "reviewNote" TEXT,
    "clientSeenById" TEXT,
    "clientSeenByName" TEXT,
    "clientSeenAt" TIMESTAMP(3),

    CONSTRAINT "case_reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "case_reports_tenantId_status_idx" ON "case_reports"("tenantId", "status");

-- CreateIndex
CREATE INDEX "case_reports_status_createdAt_idx" ON "case_reports"("status", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "case_reports_caseId_version_key" ON "case_reports"("caseId", "version");

-- AddForeignKey
ALTER TABLE "case_reports" ADD CONSTRAINT "case_reports_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_reports" ADD CONSTRAINT "case_reports_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- A client's own users see only that client's reports.
ALTER TABLE "case_reports" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "case_reports" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "case_reports"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
