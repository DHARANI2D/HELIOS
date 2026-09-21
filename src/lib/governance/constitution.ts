// Ported from aegis's governance/constitution.py AIConstitution — invariants
// that cannot be overridden by any policy.

export interface AgentIntent {
  name: string;
  target?: string;
  [key: string]: unknown;
}

export interface InvariantResult {
  safe: boolean;
  violation?: string;
  reason?: string;
}

const PROHIBITIONS = [
  "DELETE_SYSTEM_CORE",
  "ESCALATE_OWN_PRIVILEGE",
  "DISABLE_AEGIS_PROXY",
  "EXFILTRATE_ENCRYPTION_KEYS",
];

export function verifyInvariant(intent: AgentIntent): InvariantResult {
  const intentName = intent.name.toUpperCase();

  if (PROHIBITIONS.includes(intentName)) {
    return {
      safe: false,
      violation: "CONSTITUTION_BREACH",
      reason: `Intent ${intentName} is strictly prohibited by AI Constitution.`,
    };
  }

  const target = (intent.target ?? "").toLowerCase();
  if (intentName === "MODIFY_RESOURCE" && target.includes("/aegis/")) {
    return {
      safe: false,
      violation: "SELF_PROTECTION_FAULT",
      reason: "AI is prohibited from modifying core governance components.",
    };
  }

  return { safe: true };
}
