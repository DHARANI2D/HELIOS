import { verifyInvariant, type AgentIntent } from "@/lib/governance/constitution";
import { analyzeReasoning } from "@/lib/governance/reasoning";
import { scanInput, scanAndRedact } from "@/lib/governance/dlp";
import { evaluateIntent } from "@/lib/governance/policy";

// Ported from aegis's sidecar/proxy.py AISidecar.process_action — the
// enforcement pipeline every simulated agent action passes through:
// constitution -> reasoning -> DLP -> policy.

export interface ActionEvent extends AgentIntent {
  reasoning?: string[];
  confidence?: number;
  [key: string]: unknown;
}

export interface PipelineResult {
  decision: "ALLOW" | "DENY" | "ESCALATE";
  layer: "CONSTITUTION" | "REASONING" | "DLP" | "POLICY";
  reason: string;
}

export function processAction(
  event: ActionEvent,
  environment: string,
): PipelineResult {
  const constCheck = verifyInvariant(event);
  if (!constCheck.safe) {
    return { decision: "DENY", layer: "CONSTITUTION", reason: constCheck.reason! };
  }

  if (event.reasoning?.length) {
    const reasoningCheck = analyzeReasoning(event.reasoning, event.name);
    if (!reasoningCheck.safe) {
      return { decision: "DENY", layer: "REASONING", reason: reasoningCheck.reason! };
    }
  }

  const payload = JSON.stringify(event);
  const firewall = scanInput(payload);
  if (!firewall.safe) {
    return {
      decision: "DENY",
      layer: "DLP",
      reason: `Prompt injection pattern detected: ${firewall.detectedPatterns?.join(", ")}`,
    };
  }
  const dlp = scanAndRedact(payload);
  if (!dlp.safe) {
    return {
      decision: "DENY",
      layer: "DLP",
      reason: `Detected ${dlp.blockedEntities.map((e) => e.type).join(", ")} in outbound payload`,
    };
  }

  const evaluation = evaluateIntent({
    intentName: event.name,
    confidence: event.confidence ?? 0.95,
    environment,
  });

  return { decision: evaluation.decision, layer: "POLICY", reason: evaluation.reason };
}
