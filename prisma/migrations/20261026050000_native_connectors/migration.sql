-- Native connectors: actions in progress until the vendor confirms them,
-- time-boxed actions that roll back on expiry, and a per-client circuit
-- breaker for automatic containment.

-- AlterEnum
ALTER TYPE "ResponseActionStatus" ADD VALUE 'IN_PROGRESS';

-- AlterTable
ALTER TABLE "response_actions" ADD COLUMN     "expiresAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "tenants" ADD COLUMN     "automationPauseReason" TEXT,
ADD COLUMN     "automationPausedAt" TIMESTAMP(3);

