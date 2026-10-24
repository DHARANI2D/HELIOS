import type { AiAutonomy, CaseSeverity } from "@prisma/client";

// Managed-service plans: what a client buys, which SLA their cases run on,
// and what the configurator prices. Plans are your own policy, so they live
// in the service_plans table and start empty; an admin defines them in
// Build & Price → Service plans. Client-safe: parsing and SLA maths only.

export const SEVERITIES: CaseSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export type PlanFeature =
  | "monitoring"
  | "aiFirstResponse"
  | "autoContainment"
  | "threatHunting"
  | "irRetainer"
  | "reporting"
  | "dedicatedAnalyst"
  | "compliance"
  | "clientPortal"
  | "onboarding";

export const PLAN_FEATURE_LABEL: Record<PlanFeature, string> = {
  monitoring: "Analyst monitoring",
  aiFirstResponse: "AI first response (triage + initial analysis)",
  autoContainment: "Automated containment",
  threatHunting: "Proactive threat hunting",
  irRetainer: "Incident response retainer",
  reporting: "Client reporting",
  dedicatedAnalyst: "Named lead analyst",
  compliance: "Compliance evidence packs",
  clientPortal: "Client portal & approvals",
  onboarding: "Onboarding",
};

export const PLAN_FEATURES = Object.keys(PLAN_FEATURE_LABEL) as PlanFeature[];

export interface ServicePlan {
  id: string;
  key: string;
  name: string;
  tagline: string | null;
  coverage: string; // e.g. "24x7", "8x5"
  // Minutes to acknowledge, by severity (null = no SLA for that severity).
  ackMinutes: Record<CaseSeverity, number | null>;
  // Minutes to contain once acknowledged (null = no target).
  containMinutes: Record<CaseSeverity, number | null>;
  irRetainerHours: number;
  // Monthly sell price and your cost per endpoint (null until set).
  pricePerEndpoint: number | null;
  costPerEndpoint: number | null;
  onboardingMinimum: number | null;
  defaultAutonomyCap: AiAutonomy;
  // true/false, or a short description ("Monthly", "40 h / year").
  features: Partial<Record<PlanFeature, boolean | string>>;
  active: boolean;
  sortOrder: number;
}

export interface ServicePlanRow {
  id: string;
  key: string;
  name: string;
  tagline: string | null;
  coverage: string;
  ackMinutes: unknown;
  containMinutes: unknown;
  irRetainerHours: number;
  pricePerEndpoint: number | null;
  costPerEndpoint: number | null;
  onboardingMinimum: number | null;
  defaultAutonomyCap: AiAutonomy;
  features: unknown;
  active: boolean;
  sortOrder: number;
}

function minutesBySeverity(value: unknown): Record<CaseSeverity, number | null> {
  const obj = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  return Object.fromEntries(
    SEVERITIES.map((s) => {
      const v = obj[s];
      return [s, typeof v === "number" && Number.isFinite(v) && v > 0 ? v : null];
    }),
  ) as Record<CaseSeverity, number | null>;
}

export function parsePlan(row: ServicePlanRow): ServicePlan {
  const features = row.features && typeof row.features === "object" ? (row.features as Record<string, unknown>) : {};
  return {
    id: row.id,
    key: row.key,
    name: row.name,
    tagline: row.tagline,
    coverage: row.coverage,
    ackMinutes: minutesBySeverity(row.ackMinutes),
    containMinutes: minutesBySeverity(row.containMinutes),
    irRetainerHours: row.irRetainerHours,
    pricePerEndpoint: row.pricePerEndpoint,
    costPerEndpoint: row.costPerEndpoint,
    onboardingMinimum: row.onboardingMinimum,
    defaultAutonomyCap: row.defaultAutonomyCap,
    features: Object.fromEntries(
      PLAN_FEATURES.filter((f) => typeof features[f] === "boolean" || (typeof features[f] === "string" && (features[f] as string).trim() !== "")).map((f) => [f, features[f] as boolean | string]),
    ),
    active: row.active,
    sortOrder: row.sortOrder,
  };
}

export function hasFeature(plan: Pick<ServicePlan, "features">, feature: PlanFeature) {
  const v = plan.features[feature];
  return v === true || (typeof v === "string" && v.trim() !== "");
}

// Cases for a client on a plan get that plan's acknowledgement target.
// Internal cases and clients without a plan have no SLA.
export function slaDueAt(createdAt: Date, severity: CaseSeverity, plan: Pick<ServicePlan, "ackMinutes"> | null | undefined): Date | null {
  const minutes = plan?.ackMinutes[severity];
  return minutes == null ? null : new Date(createdAt.getTime() + minutes * 60_000);
}

export type SlaState = "met" | "breached" | "due" | "at_risk" | "none";

// at_risk: under 25% of the window left.
export function slaState(c: { createdAt: Date; slaDueAt: Date | null; acknowledgedAt: Date | null }, now: Date): SlaState {
  if (!c.slaDueAt) return "none";
  if (c.acknowledgedAt) return c.acknowledgedAt <= c.slaDueAt ? "met" : "breached";
  if (now > c.slaDueAt) return "breached";
  const total = c.slaDueAt.getTime() - c.createdAt.getTime();
  const left = c.slaDueAt.getTime() - now.getTime();
  return total > 0 && left / total < 0.25 ? "at_risk" : "due";
}

export function formatMinutes(minutes: number | null) {
  if (minutes == null) return "—";
  if (minutes < 60) return `${minutes} min`;
  if (minutes % 1440 === 0) return `${minutes / 1440} d`;
  if (minutes % 60 === 0) return `${minutes / 60} h`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}
