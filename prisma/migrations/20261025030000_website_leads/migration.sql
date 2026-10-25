-- Quotes requested from the public estimator carry the requester's contact.
ALTER TABLE "quotes" ADD COLUMN "source" TEXT NOT NULL DEFAULT 'app';
ALTER TABLE "quotes" ADD COLUMN "contactName" TEXT;
ALTER TABLE "quotes" ADD COLUMN "contactEmail" TEXT;
ALTER TABLE "quotes" ADD COLUMN "contactPhone" TEXT;

-- CreateIndex
CREATE INDEX "quotes_source_createdAt_idx" ON "quotes"("source", "createdAt");
