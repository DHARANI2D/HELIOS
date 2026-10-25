import type { AiAutonomy, PlaybookActionType, ResponseActionStatus } from "@prisma/client";

import { minAutonomy } from "@/lib/ai/catalog";
import { OUTCOME_RANK, type Outcome, type RuleHit } from "@/lib/rulebook/evaluate";
import { levelCap } from "@/lib/shadow/ladder";

// The containment gate between what an AI agent recommends and what happens.
// Deterministic and side-effect free so it can be tested exhaustively: the
// model proposes, this policy disposes. Each layer sets a ceiling and the
// most restrictive one wins, in a fixed order of precedence:
//   grounding → kill switch → circuit breaker → plan → client consent → client rulebook →
//   autonomy ladder → agent profile → the model's evaluation → rate limit.
// Every decision carries the reason shown to analysts and written to the
// audit chain, and a trace naming every rule that restricted it.

export interface PolicyInput {
  actionType: PlaybookActionType;
  // The target appears in the case's own evidence (see ai/grounding).
  grounded: boolean;
  confidence: number;
  killSwitch: boolean;
  // The client's circuit breaker: automatic containment paused after
  // repeated connector failures (lib/connectors/safety).
  paused?: { reason: string } | null;
  // The containment controller profile.
  autonomy: AiAutonomy;
  allowedActions: PlaybookActionType[];
  minConfidence: number;
  // The most the client's plan allows.
  planCap?: AiAutonomy;
  // What the client consented to.
  tenantCap: AiAutonomy;
  // The client's active rulebook and what it says about this action.
  rulebook?: { version: number; hash: string; hits: RuleHit[] } | null;
  // The client's autonomy ladder for this action (lib/shadow), when started.
  ladder?: { level: number } | null;
  // A model the client picked that hasn't passed its evaluation.
  modelCap?: { autonomy: AiAutonomy; reason: string } | null;
  // For host actions: the endpoint's business criticality.
  endpointCriticality?: string | null;
  autoActionsLastHour: number;
  maxAutoActionsPerHour: number;
}

export type PolicyLayer = "grounding" | "kill_switch" | "circuit_breaker" | "plan" | "consent" | "rulebook" | "ladder" | "agent" | "model" | "rate_limit";

export interface TraceEntry {
  layer: PolicyLayer;
  rule: string;
  outcome: Outcome;
  reason: string;
}

export interface PolicyDecision {
  status: Extract<ResponseActionStatus, "SUGGESTED" | "PENDING_APPROVAL" | "EXECUTED" | "BLOCKED">;
  reason: string;
  effectiveAutonomy: AiAutonomy;
  // The rule that decided, then every other rule that restricted the action.
  trace: TraceEntry[];
  approvals: number;
  policyVersion: number | null;
  policyHash: string | null;
}

// Never automated, whatever the configuration: these lock people out or are
// easy to get wrong at scale. They can still be approved by a human.
const ALWAYS_HUMAN: PlaybookActionType[] = ["DISABLE_USER", "KILL_PROCESS"];

function capOutcome(cap: AiAutonomy): Outcome {
  return cap === "AUTO_CONTAIN" ? "EXECUTED" : cap === "CONTAIN_WITH_APPROVAL" ? "PENDING_APPROVAL" : "SUGGESTED";
}

export function decideResponse(input: PolicyInput): PolicyDecision {
  const planCap = input.planCap ?? "AUTO_CONTAIN";
  const effectiveAutonomy = minAutonomy(minAutonomy(minAutonomy(input.autonomy, input.tenantCap), planCap), input.modelCap?.autonomy ?? "AUTO_CONTAIN");
  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const entries: TraceEntry[] = [];
  const add = (layer: PolicyLayer, rule: string, outcome: Outcome, reason: string) => entries.push({ layer, rule, outcome, reason });

  if (!input.grounded) add("grounding", "grounding", "BLOCKED", "Target doesn't appear in this case's evidence — the agent may have hallucinated it");
  if (input.killSwitch) add("kill_switch", "killSwitch", "SUGGESTED", "AI kill switch is on — recommendations only");
  if (input.paused) add("circuit_breaker", "tenant.automationPaused", "PENDING_APPROVAL", `Automatic containment is paused for this client (${input.paused.reason}); a person decides`);

  const plan = capOutcome(planCap);
  if (plan !== "EXECUTED") add("plan", "plan.autonomyCap", plan, plan === "SUGGESTED" ? "The client's plan allows suggestions only" : "The client's plan requires approval for containment");
  const consent = capOutcome(input.tenantCap);
  if (consent !== "EXECUTED") add("consent", "tenant.aiAutonomyCap", consent, consent === "SUGGESTED" ? "Client's AI consent allows suggestions only" : "Client requires approval for containment");

  for (const hit of input.rulebook?.hits ?? []) add("rulebook", hit.rule, hit.outcome, input.rulebook ? `${hit.reason} (rulebook v${input.rulebook.version})` : hit.reason);

  if (input.ladder) {
    const cap = levelCap(input.ladder.level);
    if (cap) add("ladder", `ladder.L${input.ladder.level}`, cap, cap === "SUGGESTED" ? `Autonomy ladder: suggestions only for this client until the AI earns more (L${input.ladder.level})` : `Autonomy ladder: approval needed for this client (L${input.ladder.level})`);
  }

  const agent = capOutcome(input.autonomy);
  if (agent === "SUGGESTED") add("agent", "agent.autonomy", "SUGGESTED", "Containment controller is set to suggest only");
  else if (agent === "PENDING_APPROVAL") add("agent", "agent.autonomy", "PENDING_APPROVAL", "Containment requires analyst approval");
  if (ALWAYS_HUMAN.includes(input.actionType)) add("agent", "agent.alwaysHuman", "PENDING_APPROVAL", "This action always needs a human");
  if (!input.allowedActions.includes(input.actionType)) add("agent", "agent.allowedActions", "PENDING_APPROVAL", "Action isn't on the pre-approved list");
  if (input.confidence < input.minConfidence) add("agent", "agent.minConfidence", "PENDING_APPROVAL", `Confidence ${pct(input.confidence)} is below the ${pct(input.minConfidence)} bar`);
  if (input.actionType === "ISOLATE_HOST" && input.endpointCriticality === "critical") add("agent", "agent.criticalEndpoint", "PENDING_APPROVAL", "Business-critical endpoint — isolation needs approval");

  if (input.modelCap) {
    const cap = capOutcome(input.modelCap.autonomy);
    if (cap !== "EXECUTED") add("model", "model.evaluation", cap, input.modelCap.reason);
  }

  if (input.autoActionsLastHour >= input.maxAutoActionsPerHour) add("rate_limit", "platform.maxAutoActionsPerHour", "PENDING_APPROVAL", `Auto-containment limit reached (${input.maxAutoActionsPerHour}/hour for this client)`);

  const status = entries.reduce<Outcome>((worst, e) => (OUTCOME_RANK[e.outcome] < OUTCOME_RANK[worst] ? e.outcome : worst), "EXECUTED");
  // The first rule (in precedence order) at the final outcome decides.
  const decider = entries.find((e) => e.outcome === status);
  const trace = decider ? [decider, ...entries.filter((e) => e !== decider)] : [];
  const approvals = Math.max(1, ...(input.rulebook?.hits ?? []).map((h) => h.approvals ?? 1));
  return {
    status,
    reason: decider?.reason ?? `Pre-approved action at ${pct(input.confidence)} confidence`,
    effectiveAutonomy,
    trace,
    approvals,
    policyVersion: input.rulebook?.version ?? null,
    policyHash: input.rulebook?.hash ?? null,
  };
}
