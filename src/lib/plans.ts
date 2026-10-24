import type { AiAutonomy, CaseSeverity } from "@prisma/client";

// Managed-service plans: what a client buys, which SLA their cases run on,
// and what the configurator prices. Client-safe.

export type PlanKey = "essentials" | "professional" | "enterprise";

export interface ServicePlan {
  key: PlanKey;
  name: string;
  tagline: string;
  coverage: "8x5" | "24x7";
  // Minutes to acknowledge, by severity (null = no SLA).
  ackMinutes: Record<CaseSeverity, number | null>;
  // Minutes to contain once acknowledged, for the severities that have a target.
  containMinutes: Partial<Record<CaseSeverity, number>>;
  defaultAutonomyCap: AiAutonomy;
  irRetainerHours: number;
  features: Record<PlanFeature, boolean | string>;
}

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

export const PLANS: Record<PlanKey, ServicePlan> = {
  essentials: {
    key: "essentials",
    name: "Essentials MDR",
    tagline: "Business-hours analysts, AI on watch around the clock",
    coverage: "8x5",
    ackMinutes: { CRITICAL: 60, HIGH: 240, MEDIUM: 1440, LOW: 4320, INFO: null },
    containMinutes: { CRITICAL: 240, HIGH: 1440 },
    defaultAutonomyCap: "CONTAIN_WITH_APPROVAL",
    irRetainerHours: 0,
    features: {
      monitoring: "8×5 analysts",
      aiFirstResponse: true,
      autoContainment: "With client approval",
      threatHunting: false,
      irRetainer: false,
      reporting: "Monthly",
      dedicatedAnalyst: false,
      compliance: false,
      clientPortal: true,
      onboarding: "Remote, self-guided",
    },
  },
  professional: {
    key: "professional",
    name: "Professional MDR",
    tagline: "24×7 SOC with automated containment",
    coverage: "24x7",
    ackMinutes: { CRITICAL: 30, HIGH: 120, MEDIUM: 480, LOW: 1440, INFO: null },
    containMinutes: { CRITICAL: 120, HIGH: 480 },
    defaultAutonomyCap: "AUTO_CONTAIN",
    irRetainerHours: 10,
    features: {
      monitoring: "24×7 analysts",
      aiFirstResponse: true,
      autoContainment: "Pre-approved actions",
      threatHunting: "Monthly",
      irRetainer: "10 h / year",
      reporting: "Weekly",
      dedicatedAnalyst: false,
      compliance: false,
      clientPortal: true,
      onboarding: "Guided, 2 weeks",
    },
  },
  enterprise: {
    key: "enterprise",
    name: "Enterprise XDR",
    tagline: "Dedicated team, continuous hunting, compliance-ready",
    coverage: "24x7",
    ackMinutes: { CRITICAL: 15, HIGH: 60, MEDIUM: 240, LOW: 720, INFO: null },
    containMinutes: { CRITICAL: 60, HIGH: 240 },
    defaultAutonomyCap: "AUTO_CONTAIN",
    irRetainerHours: 40,
    features: {
      monitoring: "24×7 analysts",
      aiFirstResponse: true,
      autoContainment: "Pre-approved actions",
      threatHunting: "Continuous",
      irRetainer: "40 h / year",
      reporting: "Weekly + quarterly review",
      dedicatedAnalyst: true,
      compliance: "ISO 27001, SOC 2, PCI DSS",
      clientPortal: true,
      onboarding: "White-glove, 4 weeks",
    },
  },
};

export const PLAN_KEYS = Object.keys(PLANS) as PlanKey[];

export function planFor(key: string | null | undefined): ServicePlan {
  return PLANS[(key as PlanKey) ?? "professional"] ?? PLANS.professional;
}

// Internal cases (no client tenant) run on the strictest targets.
export function slaDueAt(createdAt: Date, severity: CaseSeverity, plan: string | null | undefined): Date | null {
  const minutes = planFor(plan ?? "enterprise").ackMinutes[severity];
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
