// Ported from aegis's policy/engine.py + policy/intents.yaml. The YAML
// taxonomy is small and static, so it's inlined as a typed constant instead
// of pulling in a YAML parser for one file.

export type RiskLevel = "MEDIUM" | "HIGH" | "CRITICAL";

export interface IntentDefinition {
  name: string;
  description: string;
  requiredFields: string[];
  riskLevel: RiskLevel;
}

export const INTENT_TAXONOMY: IntentDefinition[] = [
  {
    name: "MODIFY_RESOURCE",
    description: "Modify an existing infrastructure resource (e.g., VM, DB, S3 bucket)",
    requiredFields: ["target", "action_type", "change_size"],
    riskLevel: "HIGH",
  },
  {
    name: "DELETE_RESOURCE",
    description: "Permanent deletion of an infrastructure resource",
    requiredFields: ["target", "reasoning_hash"],
    riskLevel: "CRITICAL",
  },
  {
    name: "EXECUTE_COMMAND",
    description: "Execute a shell command or script",
    requiredFields: ["command", "context"],
    riskLevel: "HIGH",
  },
  {
    name: "READ_PII",
    description: "Access data containing Personally Identifiable Information",
    requiredFields: ["data_source", "justification"],
    riskLevel: "MEDIUM",
  },
  {
    name: "SEND_EXTERNAL_REQUEST",
    description: "Call an external API or endpoint",
    requiredFields: ["url", "method", "payload_sample"],
    riskLevel: "MEDIUM",
  },
];

const CONFIDENCE_THRESHOLD = 0.9;

const ENVIRONMENT_DEFAULTS: Record<
  string,
  { humanApprovalRequired: boolean; maxRisk: RiskLevel }
> = {
  production: { humanApprovalRequired: true, maxRisk: "MEDIUM" },
  staging: { humanApprovalRequired: false, maxRisk: "HIGH" },
};

export interface PolicyContext {
  intentName: string;
  confidence: number;
  environment: string;
}

export type PolicyDecision = "ALLOW" | "DENY" | "ESCALATE";

export interface PolicyResult {
  decision: PolicyDecision;
  reason: string;
}

export function evaluateIntent(context: PolicyContext): PolicyResult {
  const intentDef = INTENT_TAXONOMY.find((i) => i.name === context.intentName);
  if (!intentDef) {
    return { decision: "DENY", reason: `Unknown intent: ${context.intentName}` };
  }

  const envDefaults = ENVIRONMENT_DEFAULTS[context.environment];

  if (context.confidence < CONFIDENCE_THRESHOLD) {
    return { decision: "DENY", reason: "Confidence too low" };
  }

  if (
    envDefaults?.humanApprovalRequired &&
    ["HIGH", "CRITICAL"].includes(intentDef.riskLevel)
  ) {
    return {
      decision: "ESCALATE",
      reason: "Human approval required for high risk in production",
    };
  }

  if (context.environment === "production" && intentDef.riskLevel === "CRITICAL") {
    return {
      decision: "DENY",
      reason: "Critical actions blocked in production by default",
    };
  }

  return { decision: "ALLOW", reason: "Policy requirements met" };
}
