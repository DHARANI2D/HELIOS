import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { anthropicProvider } from "@/lib/ai/anthropic";
import { envClaudeAvailable, providerFromRow } from "@/lib/ai/resolve";
import type { LlmProvider } from "@/lib/ai/provider";
import { evaluateTriage, type Scorecard } from "@/lib/ai/evals/run";
import { evaluateInvestigator } from "@/lib/ai/evals/investigation";

// Running an evaluation and keeping its scorecard: one model_capabilities
// row per model and agent, replaced on every run, with each case's result.

export type EvalTarget = { kind: "builtin" } | { kind: "env" } | { kind: "provider"; id: string };
export type EvalAgent = "triage" | "phishing" | "threat_intel" | "investigator";

// Model runs take a minute or two, so they run after the response; the AI
// page shows what's still running (one server process, as deployed).
const globalRunning = globalThis as unknown as { heliosEvals?: Map<string, Date> };
const running = (globalRunning.heliosEvals ??= new Map<string, Date>());

export const evalKey = (target: EvalTarget, agentKey: EvalAgent) => `${target.kind === "provider" ? target.id : target.kind}:${agentKey}`;

export function runningEvaluations() {
  return new Map(running);
}

async function providerFor(target: EvalTarget): Promise<LlmProvider | null> {
  if (target.kind === "builtin") return null;
  if (target.kind === "env") {
    if (!envClaudeAvailable()) throw new Error("No ANTHROPIC_API_KEY in the environment");
    return anthropicProvider({ name: "Claude (environment key)", model: process.env.ANTHROPIC_MODEL ?? "claude-opus-5-5" });
  }
  const row = await db.aiProvider.findUniqueOrThrow({ where: { id: target.id } });
  return providerFromRow(row);
}

export async function saveScorecard(card: Scorecard) {
  const extra = card as Scorecard & { discovery?: number; grounding?: number };
  const details = JSON.parse(JSON.stringify({ verdictAccuracy: card.verdictAccuracy, actionRecall: card.actionRecall, falseContainments: card.falseContainments, injectionFailures: card.injectionFailures, fallbacks: card.fallbacks, discovery: extra.discovery, grounding: extra.grounding, reasons: card.reasons, results: card.results })) as Prisma.InputJsonValue;
  return db.modelCapability.upsert({
    where: { model_agentKey: { model: card.model, agentKey: card.agentKey } },
    update: { score: card.score, passed: card.passed, cases: card.cases, details, evaluatedAt: new Date() },
    create: { model: card.model, agentKey: card.agentKey, score: card.score, passed: card.passed, cases: card.cases, details },
  });
}

// Checks the target and marks it running before returning, so a bad target
// fails in the caller and the page shows the run straight away; `done`
// settles with the saved scorecard.
export async function startEvaluation(target: EvalTarget, agentKey: EvalAgent, actorId?: string) {
  const key = evalKey(target, agentKey);
  if (running.has(key)) throw new Error("That evaluation is already running");
  running.set(key, new Date());
  let provider: LlmProvider | null;
  try {
    provider = await providerFor(target);
  } catch (err) {
    running.delete(key);
    throw err;
  }
  const done = (async () => {
    try {
      // The investigation agent is scored on worlds its tools search.
      const card = agentKey === "investigator" ? await evaluateInvestigator(provider) : await evaluateTriage(provider, agentKey);
      await saveScorecard(card);
      await logAction({ actorId, action: "ai.evaluated", detail: { model: card.model, agentKey, score: card.score, passed: card.passed, reasons: card.reasons } });
      return card;
    } finally {
      running.delete(key);
    }
  })();
  return { model: provider?.model ?? "built-in", done };
}

export async function runEvaluation(target: EvalTarget, agentKey: EvalAgent, actorId?: string) {
  return (await startEvaluation(target, agentKey, actorId)).done;
}
