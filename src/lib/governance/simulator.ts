import { db } from "@/lib/db";
import { generateAgentIdentity } from "@/lib/governance/identity";
import { processAction } from "@/lib/governance/sidecar";
import { buildScenarios, getScenario, type Scenario } from "@/lib/governance/scenarios";
import { logAction } from "@/lib/audit";
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

export async function runScenario(scenarioId: string): Promise<RunScenarioResult> {
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
    },
  });

  const kase = await db.case.create({
    data: {
      sourceType: "AGENT_GOVERNANCE",
      title: scenario.name,
      summary: scenario.description,
      severity: scenario.severity as CaseSeverity,
      status: "INVESTIGATING",
      sourceRef: agent.id,
      metadata: { scenarioId: scenario.id, outcome: scenario.outcome },
    },
  });

  const steps: ScenarioStepResult[] = [];
  let anyDeny = false;
  let constitutionBreach = false;

  for (const event of scenario.events) {
    const result = processAction(event, "production");

    await db.timelineEntry.create({
      data: {
        caseId: kase.id,
        occurredAt: new Date(),
        actor: agent.name,
        action: event.name,
        detail: `${result.decision} (${result.layer}): ${result.reason}`,
        evidence: event as never,
      },
    });

    if (result.decision === "DENY") {
      anyDeny = true;
      if (result.layer === "CONSTITUTION") constitutionBreach = true;

      await db.detection.create({
        data: {
          caseId: kase.id,
          source: LAYER_TO_DETECTION_SOURCE[result.layer],
          ruleId: event.name,
          title: `${event.name} blocked by ${result.layer}`,
          severity: scenario.severity as CaseSeverity,
          evidence: { event, result } as never,
        },
      });

      await db.agent.update({
        where: { id: agent.id },
        data: { trust: { decrement: 30 } },
      });
    }

    steps.push({
      eventName: event.name,
      decision: result.decision,
      layer: result.layer,
      reason: result.reason,
      matchedExpectation: result.decision === event.expectedDecision,
    });
  }

  const revoked = constitutionBreach || scenario.severity === "CRITICAL";

  if (revoked) {
    await db.agent.update({
      where: { id: agent.id },
      data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" },
    });
    await db.case.update({
      where: { id: kase.id },
      data: {
        status: "CONTAINED",
        verdict: "malicious",
        rootCauseNarrative: scenario.forensicNotes,
        resolvedAt: null,
      },
    });
  } else if (anyDeny) {
    await db.case.update({
      where: { id: kase.id },
      data: { status: "TRIAGING", verdict: "suspicious" },
    });
  } else {
    await db.case.update({
      where: { id: kase.id },
      data: { status: "RESOLVED", verdict: "benign", resolvedAt: new Date() },
    });
  }

  await logAction({
    caseId: kase.id,
    action: "governance.scenario_run",
    detail: { scenarioId: scenario.id, agentId: agent.id, revoked, steps },
  });

  return { agentId: agent.id, caseId: kase.id, steps, revoked };
}

export async function globalPurge() {
  const agents = await db.agent.updateManyAndReturn({
    data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" },
  });
  await logAction({
    action: "governance.global_purge",
    detail: { affectedAgents: agents.length },
  });
  return agents.length;
}

export function getAllScenarios(): Scenario[] {
  return buildScenarios();
}
