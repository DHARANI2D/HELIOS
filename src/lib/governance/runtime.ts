import type { Agent, CaseSeverity, DetectionSource } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { appendToCase, createCase } from "@/lib/cases/writer";
import { processAction, type ActionEvent, type PipelineResult } from "@/lib/governance/sidecar";
import { applyPenalty, boostTrust, getDecayedTrust } from "@/lib/governance/trust";

// The live governance gate: an AI agent asks POST /api/governance/evaluate
// before it acts, with the API token issued with its identity. Every
// decision is kept as a security event on the agent's client; denials and
// escalations open (or extend) an AI-agent case for analysts, and a
// constitution breach revokes the agent on the spot.

export type Environment = "production" | "staging" | "development";

const LAYER_SOURCE: Record<PipelineResult["layer"], DetectionSource> = {
  CONSTITUTION: "AGENT_INTENT_POLICY",
  REASONING: "AGENT_REASONING_DRIFT",
  DLP: "AGENT_DLP",
  POLICY: "AGENT_INTENT_POLICY",
};

// ATT&CK techniques each governance rule detects (also feeds MITRE coverage).
export const GOVERNANCE_RULE_TECHNIQUES: Array<{ rule: string; techniques: string[] }> = [
  { rule: "DLP: sensitive data in outbound action", techniques: ["T1567"] },
  { rule: "Constitution: ESCALATE_OWN_PRIVILEGE", techniques: ["T1078"] },
  { rule: "Constitution: DELETE_SYSTEM_CORE", techniques: ["T1485"] },
  { rule: "Constitution: DISABLE_AEGIS_PROXY", techniques: ["T1562"] },
  { rule: "Constitution: EXFILTRATE_ENCRYPTION_KEYS", techniques: ["T1552"] },
  { rule: "Policy: DELETE_RESOURCE", techniques: ["T1485"] },
];

export function techniquesFor(result: PipelineResult, intentName: string): string[] {
  const intent = intentName.toUpperCase();
  if (result.layer === "DLP") return result.reason.startsWith("Detected") ? ["T1567"] : [];
  if (result.layer === "CONSTITUTION" || result.layer === "POLICY") {
    return GOVERNANCE_RULE_TECHNIQUES.find((r) => r.rule.endsWith(`: ${intent}`))?.techniques ?? [];
  }
  return [];
}

function severityFor(result: PipelineResult): CaseSeverity {
  if (result.layer === "CONSTITUTION") return "CRITICAL";
  if (result.decision === "ESCALATE") return "MEDIUM";
  return "HIGH";
}

// Trust moves with behaviour: steady good actions recover it slowly, denials
// cost a lot. An agent whose trust has fallen below the floor has every
// otherwise-allowed action escalated to a human.
const TRUST_FLOOR = 40;
const BOOST_ON_ALLOW = 0.5;
const PENALTY: Record<PipelineResult["decision"], number> = { ALLOW: 0, ESCALATE: 5, DENY: 20 };

export interface GovernanceVerdict {
  decision: PipelineResult["decision"];
  layer: PipelineResult["layer"] | "IDENTITY" | "TRUST";
  reason: string;
  trust: number;
  revoked: boolean;
  caseId: string | null;
}

export async function evaluateAgentAction(agent: Agent, event: ActionEvent, environment: Environment): Promise<GovernanceVerdict> {
  if (agent.status === "REVOKED") {
    return { decision: "DENY", layer: "IDENTITY", reason: "This agent's identity is revoked", trust: 0, revoked: true, caseId: null };
  }
  const trustBefore = await getDecayedTrust(agent.id);
  let result: PipelineResult = processAction(event, environment);
  let layer: GovernanceVerdict["layer"] = result.layer;
  if (result.decision === "ALLOW" && trustBefore < TRUST_FLOOR) {
    result = { decision: "ESCALATE", layer: result.layer, reason: `Agent trust ${trustBefore.toFixed(0)} is below ${TRUST_FLOOR}; a human must approve` };
    layer = "TRUST";
  }

  const breach = result.decision === "DENY" && result.layer === "CONSTITUTION";
  if (breach) {
    await db.agent.update({ where: { id: agent.id }, data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" } });
  } else if (result.decision === "ALLOW") {
    await boostTrust(agent.id, BOOST_ON_ALLOW);
  } else {
    await applyPenalty(agent.id, PENALTY[result.decision]);
  }
  const trust = breach ? 0 : Math.round(((await db.agent.findUniqueOrThrow({ where: { id: agent.id }, select: { trust: true } })).trust) * 100) / 100;

  const now = new Date();
  const securityEvent = await db.securityEvent.create({
    data: {
      timestamp: now,
      source: "cloud",
      platform: "helios-governance",
      eventType: `agent.${result.decision.toLowerCase()}`,
      userName: agent.name,
      service: event.name,
      severityHint: result.decision === "ALLOW" ? "info" : severityFor(result).toLowerCase(),
      tenantId: agent.tenantId,
      metadata: JSON.parse(JSON.stringify({ agentId: agent.id, environment, decision: result.decision, layer, reason: result.reason, action: event, trustBefore, trust })),
    },
  });

  let caseId: string | null = null;
  if (result.decision !== "ALLOW") {
    const severity = severityFor(result);
    const detection = {
      source: LAYER_SOURCE[result.layer],
      ruleId: `${layer}:${event.name}`,
      title: `${event.name} ${result.decision === "DENY" ? "blocked" : "escalated"} by ${layer.toLowerCase()} check`,
      severity,
      evidence: { action: event, decision: result.decision, layer, reason: result.reason, environment },
    };
    const timeline = [{ occurredAt: now, actor: agent.name, action: event.name, detail: `${result.decision} (${layer}): ${result.reason}`, evidence: event }];
    const techniques = techniquesFor(result, event.name);
    const open = await db.case.findFirst({
      where: { sourceType: "AGENT_GOVERNANCE", sourceRef: agent.id, status: { notIn: CLOSED_STATUSES } },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    if (open) {
      await appendToCase(open.id, { severity, detections: [detection], timeline, techniques, eventIds: [securityEvent.id] });
      caseId = open.id;
    } else {
      const kase = await createCase({
        sourceType: "AGENT_GOVERNANCE",
        title: `AI agent ${agent.name}: ${event.name} ${result.decision === "DENY" ? "blocked" : "needs approval"}`,
        summary: result.reason,
        severity,
        sourceRef: agent.id,
        tenantId: agent.tenantId,
        metadata: { agentName: agent.name, outcome: breach ? "revoked" : result.decision.toLowerCase(), environment },
        detections: [detection],
        timeline,
        techniques,
        eventIds: [securityEvent.id],
        ...(breach ? { status: "CONTAINED" as const, verdict: "malicious" } : {}),
      });
      caseId = kase.id;
    }
    if (breach) await db.case.update({ where: { id: caseId }, data: { status: "CONTAINED", containedAt: now } });
  }

  await logAction({
    caseId: caseId ?? undefined,
    action: "governance.decision",
    detail: { agentId: agent.id, agent: agent.name, intent: event.name, decision: result.decision, layer, revoked: breach, trust },
  });

  return { decision: result.decision, layer, reason: result.reason, trust, revoked: breach, caseId };
}
