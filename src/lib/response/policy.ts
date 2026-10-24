import type { AiAutonomy, PlaybookActionType, ResponseActionStatus } from "@prisma/client";

import { minAutonomy } from "@/lib/ai/catalog";

// The containment gate between what an AI agent recommends and what happens.
// Deterministic and side-effect free so it can be tested exhaustively: the
// model proposes, this policy disposes. Every decision carries the reason
// shown to analysts and written to the audit chain.

export interface PolicyInput {
  actionType: PlaybookActionType;
  // The target appears in the case's own evidence (see ai/grounding).
  grounded: boolean;
  confidence: number;
  killSwitch: boolean;
  // The containment controller profile.
  autonomy: AiAutonomy;
  allowedActions: PlaybookActionType[];
  minConfidence: number;
  // What the client consented to.
  tenantCap: AiAutonomy;
  // For host actions: the endpoint's business criticality.
  endpointCriticality?: string | null;
  autoActionsLastHour: number;
  maxAutoActionsPerHour: number;
}

export interface PolicyDecision {
  status: Extract<ResponseActionStatus, "SUGGESTED" | "PENDING_APPROVAL" | "EXECUTED" | "BLOCKED">;
  reason: string;
  effectiveAutonomy: AiAutonomy;
}

// Never automated, whatever the configuration: these lock people out or are
// easy to get wrong at scale. They can still be approved by a human.
const ALWAYS_HUMAN: PlaybookActionType[] = ["DISABLE_USER", "KILL_PROCESS"];

export function decideResponse(input: PolicyInput): PolicyDecision {
  const effectiveAutonomy = minAutonomy(input.autonomy, input.tenantCap);
  const pct = (n: number) => `${Math.round(n * 100)}%`;

  if (!input.grounded) {
    return { status: "BLOCKED", effectiveAutonomy, reason: "Target doesn't appear in this case's evidence — the agent may have hallucinated it" };
  }
  if (input.killSwitch) {
    return { status: "SUGGESTED", effectiveAutonomy, reason: "AI kill switch is on — recommendations only" };
  }
  if (effectiveAutonomy === "OFF" || effectiveAutonomy === "SUGGEST") {
    const capped = input.tenantCap !== input.autonomy && effectiveAutonomy === input.tenantCap;
    return { status: "SUGGESTED", effectiveAutonomy, reason: capped ? "Client's AI consent allows suggestions only" : "Containment controller is set to suggest only" };
  }
  if (effectiveAutonomy === "CONTAIN_WITH_APPROVAL") {
    const capped = input.tenantCap === "CONTAIN_WITH_APPROVAL" && input.autonomy === "AUTO_CONTAIN";
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: capped ? "Client requires approval for containment" : "Containment requires analyst approval" };
  }

  // AUTO_CONTAIN: every guardrail must pass, otherwise a human decides.
  if (ALWAYS_HUMAN.includes(input.actionType)) {
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: "This action always needs a human" };
  }
  if (!input.allowedActions.includes(input.actionType)) {
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: "Action isn't on the pre-approved list" };
  }
  if (input.confidence < input.minConfidence) {
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: `Confidence ${pct(input.confidence)} is below the ${pct(input.minConfidence)} bar` };
  }
  if (input.actionType === "ISOLATE_HOST" && input.endpointCriticality === "critical") {
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: "Business-critical endpoint — isolation needs approval" };
  }
  if (input.autoActionsLastHour >= input.maxAutoActionsPerHour) {
    return { status: "PENDING_APPROVAL", effectiveAutonomy, reason: `Auto-containment limit reached (${input.maxAutoActionsPerHour}/hour for this client)` };
  }
  return { status: "EXECUTED", effectiveAutonomy, reason: `Pre-approved action at ${pct(input.confidence)} confidence` };
}
