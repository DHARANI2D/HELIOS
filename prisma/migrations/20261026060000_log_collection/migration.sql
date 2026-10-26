-- CreateEnum
CREATE TYPE "IngestBatchStatus" AS ENUM ('QUEUED', 'PROCESSING', 'DONE', 'FAILED');

-- AlterTable
ALTER TABLE "security_events" ADD COLUMN     "classUid" INTEGER,
ADD COLUMN     "ocsf" JSONB,
ADD COLUMN     "sourceEventId" TEXT;

-- CreateTable
CREATE TABLE "ingest_batches" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "integrationId" TEXT NOT NULL,
    "channel" TEXT NOT NULL,
    "stream" TEXT,
    "format" TEXT,
    "status" "IngestBatchStatus" NOT NULL DEFAULT 'QUEUED',
    "payload" TEXT NOT NULL,
    "bytes" INTEGER NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "availableAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "error" TEXT,
    "result" JSONB,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ingest_batches_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ingest_dead_letters" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT,
    "integrationId" TEXT NOT NULL,
    "batchId" TEXT,
    "format" TEXT,
    "reason" TEXT NOT NULL,
    "raw" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "replayedAt" TIMESTAMP(3),
    "replayedById" TEXT,

    CONSTRAINT "ingest_dead_letters_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ingest_batches_status_availableAt_idx" ON "ingest_batches"("status", "availableAt");

-- CreateIndex
CREATE INDEX "ingest_batches_tenantId_status_idx" ON "ingest_batches"("tenantId", "status");

-- CreateIndex
CREATE INDEX "ingest_batches_integrationId_receivedAt_idx" ON "ingest_batches"("integrationId", "receivedAt");

-- CreateIndex
CREATE INDEX "ingest_dead_letters_integrationId_createdAt_idx" ON "ingest_dead_letters"("integrationId", "createdAt");

-- CreateIndex
CREATE INDEX "ingest_dead_letters_tenantId_createdAt_idx" ON "ingest_dead_letters"("tenantId", "createdAt");

-- CreateIndex
CREATE INDEX "security_events_tenantId_classUid_timestamp_idx" ON "security_events"("tenantId", "classUid", "timestamp");

-- CreateIndex
CREATE UNIQUE INDEX "security_events_integrationId_sourceEventId_key" ON "security_events"("integrationId", "sourceEventId");

-- AddForeignKey
ALTER TABLE "ingest_batches" ADD CONSTRAINT "ingest_batches_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ingest_dead_letters" ADD CONSTRAINT "ingest_dead_letters_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- AlterTable
ALTER TABLE "integrations" ADD COLUMN     "quietAfterMinutes" INTEGER,
ADD COLUMN     "quietCaseId" TEXT,
ADD COLUMN     "quietSince" TIMESTAMP(3);

-- CreateTable
CREATE TABLE "collector_checkpoints" (
    "integrationId" TEXT NOT NULL,
    "stream" TEXT NOT NULL,
    "cursor" TEXT,
    "nextPollAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastPolledAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastError" TEXT,
    "failures" INTEGER NOT NULL DEFAULT 0,
    "records" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "collector_checkpoints_pkey" PRIMARY KEY ("integrationId","stream")
);

-- CreateTable
CREATE TABLE "source_health_hours" (
    "integrationId" TEXT NOT NULL,
    "hour" TIMESTAMP(3) NOT NULL,
    "events" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "source_health_hours_pkey" PRIMARY KEY ("integrationId","hour")
);

-- CreateIndex
CREATE INDEX "collector_checkpoints_nextPollAt_idx" ON "collector_checkpoints"("nextPollAt");

-- AddForeignKey
ALTER TABLE "collector_checkpoints" ADD CONSTRAINT "collector_checkpoints_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "source_health_hours" ADD CONSTRAINT "source_health_hours_integrationId_fkey" FOREIGN KEY ("integrationId") REFERENCES "integrations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

