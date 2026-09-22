-- Replace audit_logs' id (cuid) primary key with a serial `seq` column
-- for strict insertion-order chain replay; keep `id` as a unique cuid.
ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_pkey";
ALTER TABLE "audit_logs" ADD COLUMN "seq" SERIAL;
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("seq");
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_id_key" UNIQUE ("id");
DROP INDEX IF EXISTS "audit_logs_createdAt_idx";
