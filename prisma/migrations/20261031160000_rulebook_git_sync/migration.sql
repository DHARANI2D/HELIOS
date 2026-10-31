-- CreateTable
CREATE TABLE "rulebook_git_sync" (
    "tenantId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "repo" TEXT NOT NULL,
    "host" TEXT,
    "branch" TEXT NOT NULL DEFAULT 'main',
    "path" TEXT NOT NULL DEFAULT 'helios/rulebook.yaml',
    "tokenSealed" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastHash" TEXT,
    "lastVersion" INTEGER,
    "lastCheckedAt" TIMESTAMP(3),
    "lastError" TEXT,
    "createdById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "rulebook_git_sync_pkey" PRIMARY KEY ("tenantId")
);

-- AddForeignKey
ALTER TABLE "rulebook_git_sync" ADD CONSTRAINT "rulebook_git_sync_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;


ALTER TABLE "rulebook_git_sync" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "rulebook_git_sync" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "rulebook_git_sync"
  USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))
  WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true));
