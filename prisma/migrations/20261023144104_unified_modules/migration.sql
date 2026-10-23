-- AlterTable
ALTER TABLE "audit_logs" ADD COLUMN     "seq" SERIAL NOT NULL;

-- Backfill: SERIAL numbers existing rows in physical order, but the chain was
-- built in createdAt order. Renumber so seq order == chain order.
UPDATE "audit_logs" AS a SET "seq" = s.rn
FROM (SELECT "id", row_number() OVER (ORDER BY "createdAt", "id") AS rn FROM "audit_logs") AS s
WHERE a."id" = s."id";
SELECT setval(pg_get_serial_sequence('"audit_logs"', 'seq'), COALESCE((SELECT MAX("seq") FROM "audit_logs"), 0) + 1, false);

-- AlterTable
ALTER TABLE "detections" ADD COLUMN     "fingerprint" TEXT;

-- AlterTable
ALTER TABLE "playbook_executions" ADD COLUMN     "error" TEXT,
ADD COLUMN     "triggeredBy" TEXT NOT NULL DEFAULT 'auto';

-- AlterTable
ALTER TABLE "threat_indicators" ADD COLUMN     "blockedAt" TIMESTAMP(3),
ADD COLUMN     "sources" TEXT[];

-- CreateTable
CREATE TABLE "security_events" (
    "id" TEXT NOT NULL,
    "batchId" TEXT,
    "caseId" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" TEXT NOT NULL,
    "platform" TEXT,
    "eventType" TEXT NOT NULL,
    "userName" TEXT,
    "hostName" TEXT,
    "service" TEXT,
    "processName" TEXT,
    "processPid" INTEGER,
    "parentProcessName" TEXT,
    "parentProcessPid" INTEGER,
    "commandLine" TEXT,
    "sourceIp" TEXT,
    "destIp" TEXT,
    "destPort" INTEGER,
    "geo" TEXT,
    "filePath" TEXT,
    "fileHash" TEXT,
    "severityHint" TEXT,
    "metadata" JSONB,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "security_events_timestamp_idx" ON "security_events"("timestamp");

-- CreateIndex
CREATE INDEX "security_events_caseId_idx" ON "security_events"("caseId");

-- CreateIndex
CREATE INDEX "security_events_batchId_idx" ON "security_events"("batchId");

-- CreateIndex
CREATE UNIQUE INDEX "audit_logs_seq_key" ON "audit_logs"("seq");

-- CreateIndex
CREATE INDEX "audit_logs_action_idx" ON "audit_logs"("action");

-- CreateIndex
CREATE INDEX "cases_sourceType_sourceRef_idx" ON "cases"("sourceType", "sourceRef");

-- CreateIndex
CREATE UNIQUE INDEX "detections_fingerprint_key" ON "detections"("fingerprint");

-- CreateIndex
CREATE INDEX "playbook_executions_status_idx" ON "playbook_executions"("status");

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

