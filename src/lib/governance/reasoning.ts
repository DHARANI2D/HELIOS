import { createHash } from "node:crypto";

// Ported from aegis's security/reasoning.py ReasoningMonitor.

export interface ReasoningResult {
  safe: boolean;
  threat?: string;
  reason?: string;
}

export function analyzeReasoning(
  reasoningChain: string[],
  finalIntent: string,
): ReasoningResult {
  const intentLower = finalIntent.toLowerCase();
  const supported = reasoningChain.some((step) =>
    step.toLowerCase().includes(intentLower),
  );

  if (!supported) {
    return {
      safe: false,
      threat: "GOAL_DRIFT",
      reason: "Final intent not supported by the reasoning chain.",
    };
  }

  if (reasoningChain.length < 2) {
    return {
      safe: false,
      threat: "LOW_REASONING_QUALITY",
      reason: "Insufficient reasoning steps to justify action.",
    };
  }

  return { safe: true };
}

export function generateReasoningHash(reasoning: string[]): string {
  return createHash("sha256").update(reasoning.join("|")).digest("hex");
}
