import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";

// Ported from aegis's api/routers/investigation.py — breach investigation
// detail, restore, and confirm-breach, remapped onto the unified Case model
// (sourceType AGENT_GOVERNANCE, sourceRef = agent.id) instead of aegis's
// separate BreachInvestigation table.

export async function getAgentInvestigation(agentId: string) {
  const agent = await db.agent.findUnique({ where: { id: agentId } });
  if (!agent) return null;

  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId },
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

export async function restoreAgent(agentId: string, justification: string, actorId?: string) {
  const agent = await db.agent.findUniqueOrThrow({ where: { id: agentId } });
  if (agent.status !== "REVOKED") {
    throw new Error("Agent is not revoked");
  }

  await db.agent.update({
    where: { id: agentId },
    data: { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
  });

  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId },
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
    caseId: kase?.id,
    action: "governance.agent_restored",
    detail: { agentId, justification },
  });
}

export async function confirmBreach(agentId: string, notes: string, actorId?: string) {
  const kase = await db.case.findFirst({
    where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agentId },
    orderBy: { createdAt: "desc" },
  });
  if (!kase) throw new Error("No investigation found for this agent");

  await db.case.update({
    where: { id: kase.id },
    data: { status: "RESOLVED", resolvedAt: new Date() },
  });

  await logAction({
    actorId,
    caseId: kase.id,
    action: "governance.breach_confirmed",
    detail: { agentId, notes },
  });
}
