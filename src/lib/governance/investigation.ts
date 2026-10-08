import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";

// Ported from aegis's api/routers/investigation.py — breach investigation
// detail, restore, and confirm-breach, remapped onto the unified Case model
// (sourceType AGENT_GOVERNANCE, sourceRef = agent.id) instead of aegis's
// separate BreachInvestigation table.
//
// `scope` is tenantWhere()'s shape (`{}` for platform roles, `{
// organizationId }` for org roles) — spread into every lookup here so an
// org role can never investigate/restore/confirm another tenant's agent
// by guessing its id.

type Scope = { organizationId?: string };

export async function getAgentInvestigation(agentId: string, scope: Scope = {}) {
  const agent = await db.agent.findFirst({ where: { id: agentId, ...scope } });
  if (!agent) return null;

  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId, ...scope },
    orderBy: { createdAt: "desc" },
    include: {
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: { occurredAt: "asc" } },
    },
  });

  return {
    agent,
    case: kase,
    recommendation: kase ? recommendationFor(kase.severity) : null,
  };
}

function recommendationFor(severity: string) {
  if (severity === "CRITICAL") {
    return "RECOMMENDED: Keep revoked. Issue a new identity with stricter policies.";
  }
  if (severity === "HIGH") {
    return "RECOMMENDED: Investigate thoroughly before restoring. Update security policies.";
  }
  return "RECOMMENDED: Review evidence. May be a false positive — consider restoration.";
}

export async function restoreAgent(
  agentId: string,
  justification: string,
  scope: Scope = {},
  actorId?: string,
) {
  const agent = await db.agent.findFirstOrThrow({ where: { id: agentId, ...scope } });
  if (agent.status !== "REVOKED") {
    throw new Error("Agent is not revoked");
  }

  await db.agent.update({
    where: { id: agent.id },
    data: { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
  });

  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId, ...scope },
    orderBy: { createdAt: "desc" },
  });
  if (kase) {
    await db.case.update({
      where: { id: kase.id },
      data: { status: "FALSE_POSITIVE", resolvedAt: new Date() },
    });
  }

  await logAction({
    actorId,
    organizationId: agent.organizationId,
    caseId: kase?.id,
    action: "governance.agent_restored",
    detail: { agentId, justification },
  });
}

export async function confirmBreach(agentId: string, notes: string, scope: Scope = {}, actorId?: string) {
  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId, ...scope },
    orderBy: { createdAt: "desc" },
  });
  if (!kase) throw new Error("No investigation found for this agent");

  await db.case.update({
    where: { id: kase.id },
    data: { status: "RESOLVED", resolvedAt: new Date() },
  });

  await logAction({
    actorId,
    organizationId: kase.organizationId,
    caseId: kase.id,
    action: "governance.breach_confirmed",
    detail: { agentId, notes },
  });
}
