-- CreateTable
CREATE TABLE "security_tests" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "targets" JSONB NOT NULL,
    "checks" TEXT[],
    "rulesOfEngagement" TEXT NOT NULL,
    "windowStart" TIMESTAMP(3) NOT NULL,
    "windowEnd" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'requested',
    "verifyToken" TEXT NOT NULL,
    "requestedById" TEXT,
    "requestedByName" TEXT NOT NULL,
    "clientAuthorisedById" TEXT,
    "clientAuthorisedByName" TEXT,
    "clientAuthorisedAt" TIMESTAMP(3),
    "clientAttestation" TEXT,
    "heliosAuthorisedById" TEXT,
    "heliosAuthorisedByName" TEXT,
    "heliosAuthorisedAt" TIMESTAMP(3),
    "closedByName" TEXT,
    "closedReason" TEXT,
    "runs" INTEGER NOT NULL DEFAULT 0,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "probes" JSONB,
    "findings" JSONB,
    "imports" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "security_tests_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "security_tests_tenantId_createdAt_idx" ON "security_tests"("tenantId", "createdAt");

-- CreateIndex
CREATE INDEX "security_tests_status_windowStart_idx" ON "security_tests"("status", "windowStart");

-- AddForeignKey
ALTER TABLE "security_tests" ADD CONSTRAINT "security_tests_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- A client's own users see only that client's security tests.
ALTER TABLE "security_tests" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "security_tests" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "security_tests"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
