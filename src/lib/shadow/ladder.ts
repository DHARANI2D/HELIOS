import type { CaseDisposition } from "@prisma/client";

// Autonomy is earned per client and per action type, from measured
// agreement with human analysts, and taken away automatically when quality
// drops. Pure: the rules, scoring a closed case, and the promotion and
// demotion checks. lib/shadow/service.ts applies them.

export const LEVELS = [
  { level: 0, name: "Observe", ai: "Decides silently; logged only", human: "Works the case as normal" },
  { level: 1, name: "Suggest", ai: "Shows its verdict and proposed action", human: "Decides and executes" },
  { level: 2, name: "Approve", ai: "Queues the action", human: "One-tap approve or reject" },
  { level: 3, name: "Act and notify", ai: "Executes, notifies immediately", human: "Reviews, can roll back" },
  { level: 4, name: "Act", ai: "Executes, reports in the digest", human: "Samples for QA" },
] as const;
export const MAX_LEVEL = 4;

// Targets to revisit with the first pilots.
export const PROMOTION = { windowDays: 30, minDecisions: 20, minAgreement: 0.9, maxFalseContainmentRate: 0.02 };
export const DEMOTION = { windowDays: 7, minDecisions: 5, minAgreement: 0.8 };

export type LadderCap = "SUGGESTED" | "PENDING_APPROVAL" | null;

// What a level allows on its own (level 0 is handled as shadow by the caller).
export function levelCap(level: number): LadderCap {
  if (level <= 1) return "SUGGESTED";
  if (level === 2) return "PENDING_APPROVAL";
  return null;
}

// ---------------------------------------------------------------- scoring

export interface AiProposal {
  actionType: string;
  target: string | null;
  // The policy outcome it got, or would have got in shadow mode.
  outcome: string;
  status: string;
  decidedById: string | null;
  level: number | null;
  critical: boolean;
  // A QA reviewer's call on an action the AI ran on its own: right | wrong.
  qa?: string | null;
}

export interface HumanAction {
  actionType: string;
  target: string | null;
  status: string;
}

export interface ScoredDecision {
  kind: "action";
  actionType: string;
  target: string | null;
  level: number | null;
  aiOutcome: string;
  humanOutcome: "took" | "did_not";
  agreed: boolean;
  falseContainment: boolean;
  critical: boolean;
}

const same = (a: { actionType: string; target: string | null }, b: { actionType: string; target: string | null }) =>
  a.actionType === b.actionType && (a.target ?? "").toLowerCase() === (b.target ?? "").toLowerCase();
const DONE = new Set(["EXECUTED", "MANUAL_REQUIRED"]);

// Each AI proposal against what people did on the case. A human took an
// action when they ran or approved it (rolled back means they didn't want
// it). An automatic action left standing on a confirmed incident counts as
// accepted; on a false positive it was a false containment. Actions people
// took that the AI never proposed are misses.
export function scoreActions(ai: AiProposal[], human: HumanAction[], disposition: CaseDisposition): ScoredDecision[] {
  const out: ScoredDecision[] = [];
  for (const p of ai) {
    const byHand = human.some((h) => same(h, p) && DONE.has(h.status));
    const approved = !!p.decidedById && DONE.has(p.status);
    const accepted = !p.decidedById && DONE.has(p.status) && disposition === "TRUE_POSITIVE";
    // A QA review outranks inferring agreement from the disposition.
    const took = p.qa === "wrong" ? false : p.qa === "right" ? true : byHand || approved || accepted;
    out.push({
      kind: "action",
      actionType: p.actionType,
      target: p.target,
      level: p.level,
      aiOutcome: p.outcome,
      humanOutcome: took ? "took" : "did_not",
      agreed: took,
      falseContainment: p.outcome === "EXECUTED" && !took,
      critical: p.critical,
    });
  }
  for (const h of human) {
    if (!DONE.has(h.status) || ai.some((p) => same(h, p)) || out.some((o) => o.aiOutcome === "NONE" && same(o, h))) continue;
    out.push({ kind: "action", actionType: h.actionType, target: h.target, level: null, aiOutcome: "NONE", humanOutcome: "took", agreed: false, falseContainment: false, critical: false });
  }
  return out;
}

// The AI's verdict against the analyst's disposition; null when the AI
// didn't commit to one.
export function scoreVerdict(aiVerdict: string | null | undefined, disposition: CaseDisposition): { agreed: boolean } | null {
  if (!aiVerdict || aiVerdict === "needs_investigation") return null;
  const aiMalicious = aiVerdict === "true_positive" || aiVerdict === "suspicious";
  return { agreed: aiMalicious === (disposition === "TRUE_POSITIVE") };
}

// ---------------------------------------------------------------- promotion

export interface LadderStats {
  decisions: number; // AI proposals scored
  agreed: number;
  falseContainments: number;
  criticalFalseContainments: number;
  misses: number; // actions people took that the AI didn't propose
}

export const EMPTY_STATS: LadderStats = { decisions: 0, agreed: 0, falseContainments: 0, criticalFalseContainments: 0, misses: 0 };

export function agreement(s: LadderStats) {
  return s.decisions ? s.agreed / s.decisions : null;
}

export function promotionCheck(level: number, s: LadderStats): { eligible: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (level >= MAX_LEVEL) reasons.push("Already at the top level");
  if (s.decisions < PROMOTION.minDecisions) reasons.push(`${s.decisions} of ${PROMOTION.minDecisions} decisions needed`);
  const a = agreement(s);
  if (a != null && a < PROMOTION.minAgreement) reasons.push(`Agreement ${Math.round(a * 100)}% is below ${Math.round(PROMOTION.minAgreement * 100)}%`);
  if (s.criticalFalseContainments > 0) reasons.push(`${s.criticalFalseContainments} wrong containment of a critical asset`);
  const rate = s.decisions ? s.falseContainments / s.decisions : 0;
  if (rate > PROMOTION.maxFalseContainmentRate) reasons.push(`False containment rate ${(rate * 100).toFixed(1)}% is above ${PROMOTION.maxFalseContainmentRate * 100}%`);
  return { eligible: reasons.length === 0, reasons };
}

export function demotionCheck(level: number, week: LadderStats): { demote: boolean; to: number; reason: string | null } {
  if (level <= 1) return { demote: false, to: level, reason: null };
  if (week.criticalFalseContainments > 0) return { demote: true, to: 1, reason: `A critical asset was wrongly contained this week: back to suggestions` };
  const a = agreement(week);
  if (week.decisions >= DEMOTION.minDecisions && a != null && a < DEMOTION.minAgreement) {
    return { demote: true, to: level - 1, reason: `Agreement fell to ${Math.round(a * 100)}% this week (bar ${Math.round(DEMOTION.minAgreement * 100)}%)` };
  }
  return { demote: false, to: level, reason: null };
}
