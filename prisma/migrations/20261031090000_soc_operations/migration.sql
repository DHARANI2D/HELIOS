-- AlterTable
ALTER TABLE "response_actions" ADD COLUMN     "qaVerdict" TEXT;

-- CreateTable
CREATE TABLE "oncall_shifts" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'primary',
    "startsAt" TIMESTAMP(3) NOT NULL,
    "endsAt" TIMESTAMP(3) NOT NULL,
    "override" BOOLEAN NOT NULL DEFAULT false,
    "note" TEXT,
    "handoffSentAt" TIMESTAMP(3),
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oncall_shifts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oncall_pages" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "tenantId" TEXT,
    "caseId" TEXT,
    "title" TEXT NOT NULL,
    "body" TEXT,
    "severity" "CaseSeverity",
    "level" INTEGER NOT NULL DEFAULT 0,
    "pagedIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "lastPagedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ackAt" TIMESTAMP(3),
    "ackById" TEXT,
    "ackByName" TEXT,

    CONSTRAINT "oncall_pages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "runbooks" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "match" JSONB NOT NULL,
    "steps" JSONB NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdById" TEXT,
    "updatedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "runbooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_runbooks" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "tenantId" TEXT,
    "runbookId" TEXT,
    "title" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "steps" JSONB NOT NULL,
    "progress" JSONB NOT NULL DEFAULT '{}',
    "attachedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "case_runbooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "qa_reviews" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "caseId" TEXT NOT NULL,
    "week" TIMESTAMP(3) NOT NULL,
    "reasons" TEXT[],
    "weight" DOUBLE PRECISION NOT NULL,
    "reviewerId" TEXT,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "verdictRight" BOOLEAN,
    "outcome" TEXT,
    "notes" TEXT,
    "reviewedById" TEXT,
    "reviewedBy" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "qa_reviews_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "digest_runs" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "tenantId" TEXT,
    "day" TIMESTAMP(3) NOT NULL,
    "fromAt" TIMESTAMP(3) NOT NULL,
    "toAt" TIMESTAMP(3) NOT NULL,
    "recipients" INTEGER NOT NULL,
    "summary" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "digest_runs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "oncall_shifts_startsAt_endsAt_idx" ON "oncall_shifts"("startsAt", "endsAt");

-- CreateIndex
CREATE UNIQUE INDEX "oncall_pages_key_key" ON "oncall_pages"("key");

-- CreateIndex
CREATE INDEX "oncall_pages_ackAt_lastPagedAt_idx" ON "oncall_pages"("ackAt", "lastPagedAt");

-- CreateIndex
CREATE INDEX "runbooks_tenantId_idx" ON "runbooks"("tenantId");

-- CreateIndex
CREATE INDEX "case_runbooks_tenantId_idx" ON "case_runbooks"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "case_runbooks_caseId_runbookId_key" ON "case_runbooks"("caseId", "runbookId");

-- CreateIndex
CREATE INDEX "qa_reviews_week_status_idx" ON "qa_reviews"("week", "status");

-- CreateIndex
CREATE INDEX "qa_reviews_tenantId_idx" ON "qa_reviews"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "qa_reviews_caseId_week_key" ON "qa_reviews"("caseId", "week");

-- CreateIndex
CREATE UNIQUE INDEX "digest_runs_key_key" ON "digest_runs"("key");

-- CreateIndex
CREATE INDEX "digest_runs_tenantId_day_idx" ON "digest_runs"("tenantId", "day");

-- AddForeignKey
ALTER TABLE "oncall_shifts" ADD CONSTRAINT "oncall_shifts_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_runbooks" ADD CONSTRAINT "case_runbooks_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_runbooks" ADD CONSTRAINT "case_runbooks_runbookId_fkey" FOREIGN KEY ("runbookId") REFERENCES "runbooks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "qa_reviews" ADD CONSTRAINT "qa_reviews_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;


ALTER TABLE "oncall_pages" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "oncall_pages" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "oncall_pages"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "runbooks" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "runbooks" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "runbooks"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "case_runbooks" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "case_runbooks" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "case_runbooks"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "qa_reviews" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "qa_reviews" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "qa_reviews"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));

ALTER TABLE "digest_runs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "digest_runs" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "digest_runs"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
