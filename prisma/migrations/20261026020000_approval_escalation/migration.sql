-- Pending approvals walk the client's approver chain; this records the step.

-- AlterTable
ALTER TABLE "response_actions" ADD COLUMN     "escalation" JSONB;

