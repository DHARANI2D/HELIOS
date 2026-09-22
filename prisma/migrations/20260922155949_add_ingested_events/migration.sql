-- CreateEnum
CREATE TYPE "EventSource" AS ENUM ('AUTH', 'ENDPOINT', 'NETWORK', 'CLOUD');

-- CreateTable
CREATE TABLE "ingested_events" (
    "id" TEXT NOT NULL,
    "source" "EventSource" NOT NULL,
    "eventType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actorUser" TEXT,
    "actorProcess" TEXT,
    "actorService" TEXT,
    "sourceIp" TEXT,
    "destIp" TEXT,
    "geo" TEXT,
    "severityHint" "CaseSeverity" NOT NULL DEFAULT 'INFO',
    "confidenceHint" DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    "metadata" JSONB NOT NULL,
    "caseId" TEXT,

    CONSTRAINT "ingested_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ingested_events_timestamp_idx" ON "ingested_events"("timestamp");

-- CreateIndex
CREATE INDEX "ingested_events_actorUser_idx" ON "ingested_events"("actorUser");

-- CreateIndex
CREATE INDEX "ingested_events_sourceIp_idx" ON "ingested_events"("sourceIp");

-- AddForeignKey
ALTER TABLE "ingested_events" ADD CONSTRAINT "ingested_events_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;
