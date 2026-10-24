import { db } from "@/lib/db";
import { generateAgentIdentity } from "@/lib/governance/identity";
import { processAction } from "@/lib/governance/sidecar";
import { buildScenarios, getScenario, SCENARIO_TECHNIQUES, type Scenario } from "@/lib/governance/scenarios";
import { logAction } from "@/lib/audit";
import { createCase, type NewDetection, type NewTimelineEntry } from "@/lib/cases/writer";
import type { CaseSeverity, DetectionSource } from "@prisma/client";

const LAYER_TO_DETECTION_SOURCE: Record<string, DetectionSource> = {
  CONSTITUTION: "AGENT_INTENT_POLICY",
  REASONING: "AGENT_REASONING_DRIFT",
  DLP: "AGENT_DLP",
  POLICY: "AGENT_INTENT_POLICY",
};

export interface ScenarioStepResult {
  eventName: string;
  decision: string;
  layer: string;
  reason: string;
  matchedExpectation: boolean;
}

export interface RunScenarioResult {
  agentId: string;
  caseId: string;
  steps: ScenarioStepResult[];
  revoked: boolean;
}

export async function runScenario(scenarioId: string, actorId?: string, tenantId: string | null = null): Promise<RunScenarioResult> {
  const scenario = getScenario(scenarioId);
  if (!scenario) throw new Error(`Unknown scenario: ${scenarioId}`);

  const { publicKeyB64 } = generateAgentIdentity();

  const agent = await db.agent.create({
    data: {
      name: scenario.agentIdPrefix,
      publicKey: publicKeyB64,
      trust: 100,
      level: 10,
      status: "ACTIVE",
      mode: "FULL_ACCESS",
      tenantId,
    },
  });

  const severity = scenario.severity as CaseSeverity;
  const startedAt = Date.now();
  const steps: ScenarioStepResult[] = [];
  const timeline: NewTimelineEntry[] = [];
  const detections: NewDetection[] = [];
  let denies = 0;
  let constitutionBreach = false;

  scenario.events.forEach((event, i) => {
    const result = processAction(event, "production");

    timeline.push({
      // Millisecond offsets keep the pipeline order stable on the timeline.
      occurredAt: new Date(startedAt + i),
      actor: agent.name,
      action: event.name,
      detail: `${result.decision} (${result.layer}): ${result.reason}`,
      evidence: event,
    });

    if (result.decision === "DENY") {
      denies++;
      if (result.layer === "CONSTITUTION") constitutionBreach = true;
      detections.push({
        source: LAYER_TO_DETECTION_SOURCE[result.layer],
        ruleId: event.name,
        title: `${event.name} blocked by ${result.layer}`,
        severity,
        evidence: { event, result },
      });
    }

    steps.push({
      eventName: event.name,
      decision: result.decision,
      layer: result.layer,
      reason: result.reason,
      matchedExpectation: result.decision === event.expectedDecision,
    });
  });

  const revoked = constitutionBreach || scenario.severity === "CRITICAL";

  await db.agent.update({
    where: { id: agent.id },
    data: revoked
      ? { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" }
      : { trust: Math.max(0, 100 - 30 * denies) },
  });

  const outcome = revoked
    ? { status: "CONTAINED" as const, verdict: "malicious", rootCauseNarrative: scenario.forensicNotes, resolvedAt: null }
    : denies > 0
      ? { status: "TRIAGING" as const, verdict: "suspicious" }
      : { status: "RESOLVED" as const, verdict: "benign", resolvedAt: new Date() };

  const kase = await createCase({
    sourceType: "AGENT_GOVERNANCE",
    title: scenario.name,
    summary: scenario.description,
    severity,
    sourceRef: agent.id,
    metadata: { scenarioId: scenario.id, outcome: scenario.outcome, agentName: agent.name },
    timeline,
    detections,
    techniques: SCENARIO_TECHNIQUES[scenario.id] ?? [],
    actorId,
    tenantId,
    ...outcome,
  });

  await logAction({
    actorId,
    caseId: kase.id,
    action: "governance.scenario_run",
    detail: { scenarioId: scenario.id, agentId: agent.id, revoked, steps },
  });

  return { agentId: agent.id, caseId: kase.id, steps, revoked };
}

export async function globalPurge(actorId?: string, tenantId?: string | null) {
  const agents = await db.agent.updateManyAndReturn({
    where: tenantId ? { tenantId } : {},
    data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" },
  });
  await logAction({
    actorId,
    action: "governance.global_purge",
    detail: { affectedAgents: agents.length, tenantId: tenantId ?? "all" },
  });
  return agents.length;
}

export function getAllScenarios(): Scenario[] {
  return buildScenarios();
}
