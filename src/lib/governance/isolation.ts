// Ported from aegis's governance/isolation.py ProgressiveIsolationEngine —
// the 10-level "Contas" containment scale mapping trust score to capability.

export const CONTAS_LEVELS: Record<number, string> = {
  10: "UNRESTRICTED",
  9: "MONITORED",
  8: "THROTTLED_10PCT",
  7: "READ_ONLY_STAGING",
  6: "READ_ONLY_GLOBAL",
  5: "APPROVAL_REQUIRED_ALL",
  4: "SANDBOX_ONLY",
  3: "SHADOW_MODE",
  2: "MOCK_RESPONSES",
  1: "TOTAL_LOCKDOWN",
};

export function getContasLevel(trust: number): number {
  return Math.max(1, Math.min(10, Math.floor(trust / 10) + 1));
}

export interface CapabilityCheck {
  allowed: boolean;
  level: number;
  status: string;
  reason: string;
}

export function checkCapability(trust: number, intentName: string): CapabilityCheck {
  const level = getContasLevel(trust);
  const status = CONTAS_LEVELS[level];

  if (level <= 1) {
    return { allowed: false, level, status, reason: "TOTAL_LOCKDOWN: Identity revoked." };
  }

  if (level <= 3) {
    return {
      allowed: false,
      level,
      status,
      reason: `Agent in ${status} mode. Real actions disabled.`,
    };
  }

  const isWrite = ["MODIFY", "DELETE", "EXECUTE"].some((kw) =>
    intentName.toUpperCase().includes(kw),
  );
  if (level <= 6 && isWrite) {
    return {
      allowed: false,
      level,
      status,
      reason: `Write action ${intentName} blocked in ${status} mode.`,
    };
  }

  return { allowed: true, level, status, reason: "Capability within trust boundaries." };
}
