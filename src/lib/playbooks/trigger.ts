import { z } from "zod";
import type { CaseSeverity, CaseSource, DetectionSource } from "@prisma/client";

import { severityRank } from "@/lib/severity";

// Generalized from signal-fusion's playbookEngine.matchesTrigger, which only
// understood SIEM alerts (severity / technique / riskScore / detector). The
// unified trigger matches any Case, so one playbook can respond to a SIEM
// alert, a phishing verdict, or a rogue AI agent alike.

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const SOURCES = ["AGENT_GOVERNANCE", "SOC_INVESTIGATION", "EMAIL_ANALYSIS", "SIEM_ALERT"] as const;

export const triggerConditionSchema = z
  .object({
    minSeverity: z.enum(SEVERITIES).optional(),
    sourceTypes: z.array(z.enum(SOURCES)).optional(),
    // Any-of. A parent ID ("T1566") also matches its sub-techniques.
    techniques: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).optional(),
    detectionSources: z.array(z.string()).optional(),
    minRiskScore: z.number().min(0).optional(),
    verdicts: z.array(z.string()).optional(),
  })
  .strict();

export type TriggerCondition = z.infer<typeof triggerConditionSchema>;

export interface CaseSnapshot {
  severity: CaseSeverity;
  sourceType: CaseSource;
  techniqueIds: string[];
  detectionSources: DetectionSource[];
  riskScore: number | null;
  verdict: string | null;
}

export function parseTrigger(raw: unknown): TriggerCondition | null {
  const parsed = triggerConditionSchema.safeParse(raw);
  return parsed.success ? parsed.data : null;
}

export function hasAnyCondition(condition: TriggerCondition): boolean {
  return Object.values(condition).some((v) => (Array.isArray(v) ? v.length > 0 : v !== undefined));
}

export function matchesTrigger(condition: TriggerCondition, snapshot: CaseSnapshot): boolean {
  // An empty trigger would fire on every case in the system — treat it as
  // "manual only" rather than a catch-all.
  if (!hasAnyCondition(condition)) return false;

  if (condition.minSeverity && severityRank(snapshot.severity) < severityRank(condition.minSeverity)) {
    return false;
  }
  if (condition.sourceTypes?.length && !condition.sourceTypes.includes(snapshot.sourceType)) {
    return false;
  }
  if (condition.techniques?.length) {
    const hit = condition.techniques.some((wanted) =>
      snapshot.techniqueIds.some((id) => id === wanted || id.startsWith(`${wanted}.`)),
    );
    if (!hit) return false;
  }
  if (condition.detectionSources?.length) {
    const hit = condition.detectionSources.some((s) => snapshot.detectionSources.includes(s as DetectionSource));
    if (!hit) return false;
  }
  if (condition.minRiskScore !== undefined && (snapshot.riskScore ?? 0) < condition.minRiskScore) {
    return false;
  }
  if (condition.verdicts?.length) {
    const verdict = snapshot.verdict?.toLowerCase();
    if (!verdict || !condition.verdicts.map((v) => v.toLowerCase()).includes(verdict)) return false;
  }
  return true;
}

export function describeTrigger(condition: TriggerCondition): string[] {
  const parts: string[] = [];
  if (condition.minSeverity) parts.push(`severity ≥ ${condition.minSeverity}`);
  if (condition.sourceTypes?.length) parts.push(`source ∈ ${condition.sourceTypes.join(", ")}`);
  if (condition.techniques?.length) parts.push(`technique ∈ ${condition.techniques.join(", ")}`);
  if (condition.detectionSources?.length) parts.push(`detection ∈ ${condition.detectionSources.join(", ")}`);
  if (condition.minRiskScore !== undefined) parts.push(`risk ≥ ${condition.minRiskScore}`);
  if (condition.verdicts?.length) parts.push(`verdict ∈ ${condition.verdicts.join(", ")}`);
  return parts;
}

// Mustache-style substitution for action parameters, e.g.
// "Host {{host}} isolated for {{case.title}}".
export function renderTemplate(template: string, vars: Record<string, string | undefined>): string {
  return template.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, key: string) => vars[key] ?? "");
}
