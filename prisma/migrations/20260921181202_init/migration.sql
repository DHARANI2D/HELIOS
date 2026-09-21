-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('ANALYST', 'ADMIN');

-- CreateEnum
CREATE TYPE "CaseSource" AS ENUM ('AGENT_GOVERNANCE', 'SOC_INVESTIGATION', 'EMAIL_ANALYSIS', 'SIEM_ALERT');

-- CreateEnum
CREATE TYPE "CaseSeverity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "CaseStatus" AS ENUM ('OPEN', 'TRIAGING', 'INVESTIGATING', 'AWAITING_APPROVAL', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "DetectionSource" AS ENUM ('GEO_VELOCITY', 'FSM_CHAIN', 'ANOMALOUS_ACTION', 'THREAT_INTEL_MATCH', 'RECONNAISSANCE', 'CREDENTIAL_HARVESTING', 'LATERAL_MOVEMENT', 'DATA_EXFILTRATION', 'PERSISTENCE', 'DEFENSE_EVASION', 'IMPACT', 'AGENT_INTENT_POLICY', 'AGENT_DLP', 'AGENT_REASONING_DRIFT', 'AGENT_TRUST_DECAY', 'EMAIL_HEADER_AUTH', 'EMAIL_BODY_URL', 'EMAIL_ATTACHMENT_FORENSICS', 'EMAIL_SANDBOX_DETONATION');

-- CreateEnum
CREATE TYPE "IndicatorType" AS ENUM ('IP', 'DOMAIN', 'URL', 'FILE_HASH', 'EMAIL_ADDRESS');

-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('ACTIVE', 'ISOLATED', 'REVOKED');

-- CreateEnum
CREATE TYPE "PlaybookActionType" AS ENUM ('ISOLATE_HOST', 'BLOCK_IP', 'NOTIFY_SLACK', 'CREATE_TICKET', 'KILL_PROCESS', 'COLLECT_LOGS', 'REVOKE_AGENT', 'RESTORE_AGENT');

-- CreateEnum
CREATE TYPE "PlaybookExecutionStatus" AS ENUM ('PENDING_APPROVAL', 'RUNNING', 'SUCCEEDED', 'FAILED', 'REJECTED');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "passwordHash" TEXT,
    "role" "UserRole" NOT NULL DEFAULT 'ANALYST',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "accounts" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "providerAccountId" TEXT NOT NULL,
    "refresh_token" TEXT,
    "access_token" TEXT,
    "expires_at" INTEGER,
    "token_type" TEXT,
    "scope" TEXT,
    "id_token" TEXT,
    "session_state" TEXT,

    CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" TEXT NOT NULL,
    "sessionToken" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expires" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cases" (
    "id" TEXT NOT NULL,
    "sourceType" "CaseSource" NOT NULL,
    "title" TEXT NOT NULL,
    "summary" TEXT,
    "severity" "CaseSeverity" NOT NULL DEFAULT 'MEDIUM',
    "status" "CaseStatus" NOT NULL DEFAULT 'OPEN',
    "confidence" DOUBLE PRECISION,
    "verdict" TEXT,
    "riskScore" DOUBLE PRECISION,
    "assignedToId" TEXT,
    "sourceRef" TEXT,
    "rootCauseNarrative" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "cases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "timeline_entries" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "occurredAt" TIMESTAMP(3) NOT NULL,
    "actor" TEXT,
    "action" TEXT NOT NULL,
    "detail" TEXT,
    "evidence" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "timeline_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detections" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "source" "DetectionSource" NOT NULL,
    "ruleId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "CaseSeverity" NOT NULL,
    "evidence" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "detections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mitre_tactics" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,

    CONSTRAINT "mitre_tactics_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mitre_techniques" (
    "id" TEXT NOT NULL,
    "tacticId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "isSubtechnique" BOOLEAN NOT NULL DEFAULT false,
    "parentId" TEXT,

    CONSTRAINT "mitre_techniques_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_mitre_techniques" (
    "caseId" TEXT NOT NULL,
    "techniqueId" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION,

    CONSTRAINT "case_mitre_techniques_pkey" PRIMARY KEY ("caseId","techniqueId")
);

-- CreateTable
CREATE TABLE "threat_indicators" (
    "id" TEXT NOT NULL,
    "type" "IndicatorType" NOT NULL,
    "value" TEXT NOT NULL,
    "maliciousScore" DOUBLE PRECISION,
    "providerData" JSONB NOT NULL,
    "lastCheckedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threat_indicators_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_indicators" (
    "caseId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "role" TEXT,

    CONSTRAINT "case_indicators_pkey" PRIMARY KEY ("caseId","indicatorId")
);

-- CreateTable
CREATE TABLE "agents" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "trust" DOUBLE PRECISION NOT NULL DEFAULT 100,
    "level" INTEGER NOT NULL DEFAULT 10,
    "status" "AgentStatus" NOT NULL DEFAULT 'ACTIVE',
    "mode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUpdateAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbooks" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "triggerCondition" JSONB NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "autoExecute" BOOLEAN NOT NULL DEFAULT false,
    "requireApproval" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "playbooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_actions" (
    "id" TEXT NOT NULL,
    "playbookId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "actionType" "PlaybookActionType" NOT NULL,
    "parameters" JSONB NOT NULL,
    "order" INTEGER NOT NULL,

    CONSTRAINT "playbook_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_executions" (
    "id" TEXT NOT NULL,
    "playbookId" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "status" "PlaybookExecutionStatus" NOT NULL DEFAULT 'PENDING_APPROVAL',
    "results" JSONB,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "playbook_executions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_approvals" (
    "id" TEXT NOT NULL,
    "executionId" TEXT NOT NULL,
    "approverId" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "notes" TEXT,
    "decidedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "playbook_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_logs" (
    "id" TEXT NOT NULL,
    "actorId" TEXT,
    "caseId" TEXT,
    "action" TEXT NOT NULL,
    "detail" JSONB,
    "prevHash" TEXT NOT NULL,
    "currentHash" TEXT NOT NULL,
    "signature" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "accounts_provider_providerAccountId_key" ON "accounts"("provider", "providerAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_sessionToken_key" ON "sessions"("sessionToken");

-- CreateIndex
CREATE INDEX "cases_sourceType_status_idx" ON "cases"("sourceType", "status");

-- CreateIndex
CREATE INDEX "cases_severity_idx" ON "cases"("severity");

-- CreateIndex
CREATE INDEX "timeline_entries_caseId_occurredAt_idx" ON "timeline_entries"("caseId", "occurredAt");

-- CreateIndex
CREATE INDEX "detections_caseId_idx" ON "detections"("caseId");

-- CreateIndex
CREATE INDEX "detections_source_idx" ON "detections"("source");

-- CreateIndex
CREATE INDEX "threat_indicators_expiresAt_idx" ON "threat_indicators"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "threat_indicators_type_value_key" ON "threat_indicators"("type", "value");

-- CreateIndex
CREATE UNIQUE INDEX "agents_name_key" ON "agents"("name");

-- CreateIndex
CREATE INDEX "audit_logs_createdAt_idx" ON "audit_logs"("createdAt");

-- AddForeignKey
ALTER TABLE "accounts" ADD CONSTRAINT "accounts_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cases" ADD CONSTRAINT "cases_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "timeline_entries" ADD CONSTRAINT "timeline_entries_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "detections" ADD CONSTRAINT "detections_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mitre_techniques" ADD CONSTRAINT "mitre_techniques_tacticId_fkey" FOREIGN KEY ("tacticId") REFERENCES "mitre_tactics"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_mitre_techniques" ADD CONSTRAINT "case_mitre_techniques_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_mitre_techniques" ADD CONSTRAINT "case_mitre_techniques_techniqueId_fkey" FOREIGN KEY ("techniqueId") REFERENCES "mitre_techniques"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_indicators" ADD CONSTRAINT "case_indicators_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_indicators" ADD CONSTRAINT "case_indicators_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "threat_indicators"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_actions" ADD CONSTRAINT "playbook_actions_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "playbooks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_playbookId_fkey" FOREIGN KEY ("playbookId") REFERENCES "playbooks"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_executions" ADD CONSTRAINT "playbook_executions_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_approvals" ADD CONSTRAINT "playbook_approvals_executionId_fkey" FOREIGN KEY ("executionId") REFERENCES "playbook_executions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "playbook_approvals" ADD CONSTRAINT "playbook_approvals_approverId_fkey" FOREIGN KEY ("approverId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;
