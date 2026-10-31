import { createHash } from "node:crypto";
import type { CaseSeverity } from "@prisma/client";

// QA sampling, pure. Even at the top of the autonomy ladder, a share of the
// cases the AI handled on its own goes to a person each week, weighted
// toward high severity, new detection rules and critical assets. The draw
// is weighted sampling without replacement (Efraimidis and Spirakis: each
// case gets the key u^(1/weight) and the largest keys are taken), with u
// derived from the week and the case, so the same week always draws the
// same cases.

export interface QaCandidate {
  caseId: string;
  tenantId: string | null;
  severity: CaseSeverity;
  // Actions the AI ran with nobody approving them.
  autonomousActions: number;
  // The AI's verdict was benign.
  aiBenign: boolean;
  // Raised by a detection rule that went live in the last 30 days.
  newRule: boolean;
  // An autonomous action touched a critical asset.
  criticalTarget: boolean;
}

export function qaWeight(c: QaCandidate): { weight: number; reasons: string[] } {
  const reasons: string[] = [];
  let weight = 1;
  if (c.autonomousActions) reasons.push(`AI acted on its own (${c.autonomousActions})`);
  if (c.aiBenign) reasons.push("AI called it benign");
  const factor = (x: number, why: string) => {
    weight *= x;
    reasons.push(why);
  };
  if (c.severity === "CRITICAL") factor(4, "critical severity");
  else if (c.severity === "HIGH") factor(3, "high severity");
  if (c.newRule) factor(2, "new detection rule");
  if (c.criticalTarget) factor(2, "action on a critical asset");
  return { weight, reasons };
}

export const sampleSize = (population: number, sharePct: number, min: number) => Math.min(population, Math.max(min, Math.ceil((population * sharePct) / 100)));

// A uniform number in (0, 1) from the seed and the case.
function unit(seed: string, id: string) {
  const h = createHash("sha256").update(`${seed}|${id}`).digest();
  return (h.readUIntBE(0, 6) + 1) / (2 ** 48 + 2);
}

export function weightedSample<T extends { caseId: string }>(items: Array<T & { weight: number }>, n: number, seed: string): Array<T & { weight: number }> {
  return items
    .map((x) => ({ x, key: Math.log(unit(seed, x.caseId)) / x.weight }))
    .sort((a, b) => b.key - a.key)
    .slice(0, Math.max(0, n))
    .map((k) => k.x);
}

// Monday 00:00 UTC of the week a moment falls in.
export function weekStart(d: Date) {
  const day = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  return new Date(day.getTime() - ((day.getUTCDay() + 6) % 7) * 86_400_000);
}
