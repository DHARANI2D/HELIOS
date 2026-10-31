import type { ResponseAction } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { aiSettings } from "@/lib/settings";
import { ACTION_LABEL } from "@/lib/response/labels";
import { AI_INITIAL_CONTAINMENT } from "@/lib/response/policy";
import { OUTCOME_RANK, type Outcome } from "@/lib/rulebook/evaluate";
import { activeRulebook, rulebookVerdict } from "@/lib/rulebook/service";
import { levelCap } from "@/lib/shadow/ladder";

// The second, independent check on containment the AI runs on its own,
// made at the moment of acting rather than when the AI proposed it. The
// policy (lib/response/policy.ts) decided once; this re-reads the rules in
// force now and refuses anything they no longer allow.
//
// Two kinds of "no":
// - The rules moved on in between (a version came into force, consent was
//   lowered, the kill switch went on): the action waits for a person, or
//   becomes a suggestion. That's the system working.
// - Something that should be impossible: an AI action outside initial
//   containment, decided under no rulebook or one that isn't the version in
//   force, or a rulebook whose text no longer matches what was approved.
//   That's a violation: the action is blocked, automatic containment for
//   the client is paused (circuit breaker), and the SOC is paged.

export type GuardVerdict = { ok: true } | { ok: false; status: Exclude<Outcome, "EXECUTED">; reason: string; violation: boolean };

const AUTONOMY_ORDER = ["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"] as const;
const capOutcome = (cap: string): Outcome => (cap === "AUTO_CONTAIN" ? "EXECUTED" : cap === "CONTAIN_WITH_APPROVAL" ? "PENDING_APPROVAL" : "SUGGESTED");

// Containment the AI is about to run with nobody's approval.
export function isAutonomous(action: Pick<ResponseAction, "source" | "decidedById" | "approvals">) {
  return action.source === "ai" && !action.decidedById && !(Array.isArray(action.approvals) && action.approvals.length > 0);
}

export async function checkAutonomousAction(action: ResponseAction): Promise<GuardVerdict> {
  const violation = (reason: string): GuardVerdict => ({ ok: false, status: "BLOCKED", reason, violation: true });
  const hold = (status: Exclude<Outcome, "EXECUTED">, reason: string): GuardVerdict => ({ ok: false, status, reason: `Held at the moment of acting: ${reason}`, violation: false });

  if (!AI_INITIAL_CONTAINMENT.includes(action.actionType)) return violation(`${ACTION_LABEL[action.actionType]} is beyond the AI's initial containment`);

  const [settings, kase, tenant] = await Promise.all([
    aiSettings(),
    db.case.findUnique({ where: { id: action.caseId }, select: { severity: true } }),
    action.tenantId ? db.tenant.findUnique({ where: { id: action.tenantId }, select: { aiAutonomyCap: true, automationPausedAt: true, plan: { select: { defaultAutonomyCap: true } } } }) : null,
  ]);
  if (!kase) return violation("its case is gone");

  // The rulebook it was decided under must be the one in force, unaltered.
  const rb = action.tenantId ? await activeRulebook(action.tenantId, true) : null;
  if (rb?.tampered) return violation(`rulebook v${rb.version} doesn't match the text that was approved`);
  if (rb && action.policyHash !== rb.hash) {
    if (!action.policyHash) return violation(`it was decided without rulebook v${rb.version}, which is in force`);
    // A newer version came into force while it was on its way: decide again.
    return hold("PENDING_APPROVAL", `rulebook v${rb.version} came into force after the AI decided; a person decides`);
  }
  if (!rb && action.policyHash) return hold("PENDING_APPROVAL", "the rulebook it was decided under is no longer in force; a person decides");

  if (settings.killSwitch) return hold("SUGGESTED", "the AI kill switch is on");
  if (tenant?.automationPausedAt) return hold("PENDING_APPROVAL", "automatic containment is paused for this client");
  for (const [label, cap] of [["the client's AI consent", tenant?.aiAutonomyCap], ["the client's plan", tenant?.plan?.defaultAutonomyCap]] as const) {
    if (cap && AUTONOMY_ORDER.includes(cap) && capOutcome(cap) !== "EXECUTED") return hold(capOutcome(cap) as Exclude<Outcome, "EXECUTED">, `${label} no longer allows automatic containment`);
  }
  if (action.tenantId) {
    const level = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId: action.tenantId, actionType: action.actionType } }, select: { level: true } });
    const cap = level ? (level.level === 0 ? "SUGGESTED" : levelCap(level.level)) : null;
    if (cap) return hold(cap, `the autonomy ladder is at L${level!.level} for this action`);
  }
  // What the rulebook says right now about this action on this target.
  const verdict = await rulebookVerdict({ tenantId: action.tenantId, actionType: action.actionType, target: action.target, severity: kase.severity, fresh: true });
  const worst = (verdict?.hits ?? []).reduce<{ outcome: Outcome; reason: string } | null>((w, h) => (OUTCOME_RANK[h.outcome] < OUTCOME_RANK[w?.outcome ?? "EXECUTED"] ? { outcome: h.outcome, reason: h.reason } : w), null);
  if (worst) return hold(worst.outcome as Exclude<Outcome, "EXECUTED">, worst.reason);
  return { ok: true };
}

// A violation: block, pause the client's automatic containment, tell the SOC.
export async function reportViolation(action: Pick<ResponseAction, "id" | "caseId" | "tenantId" | "actionType" | "target">, reason: string) {
  await logAction({ caseId: action.caseId, action: "containment.policy_violation", detail: { responseActionId: action.id, actionType: action.actionType, target: action.target, tenantId: action.tenantId, reason } });
  if (action.tenantId) {
    const { pauseAutomation } = await import("@/lib/connectors/safety");
    await pauseAutomation(action.tenantId, `AI containment outside the approved rules was stopped: ${reason}`);
  }
  await notify(await staffFor(["SOC_MANAGER", "ADMIN"]), {
    kind: "ai",
    title: `Stopped: AI containment outside the approved rules`,
    body: `${ACTION_LABEL[action.actionType]}${action.target ? ` ${action.target}` : ""}: ${reason}. Automatic containment for this client is paused until someone reviews it.`,
    caseId: action.caseId,
  });
}

// The monitor (a background job every five minutes): re-checks containment
// the AI ran on its own in the last day. Anything beyond initial
// containment, or decided under rulebook text never approved for that
// client, is reported once as a violation: the client's automatic
// containment is paused and the SOC is paged.
export async function monitorAutonomousContainment(now = new Date(), windowMs = 24 * 3_600_000) {
  const since = new Date(now.getTime() - windowMs);
  const actions = await db.responseAction.findMany({
    where: { source: "ai", decidedById: null, status: { in: ["EXECUTED", "IN_PROGRESS"] }, createdAt: { gte: since } },
    select: { id: true, caseId: true, tenantId: true, actionType: true, target: true, policyHash: true, approvals: true },
    take: 2000,
  });
  if (!actions.length) return 0;
  const reported = new Set(
    (await db.auditLog.findMany({ where: { action: "containment.policy_violation", createdAt: { gte: new Date(since.getTime() - windowMs) } }, select: { detail: true } }))
      .map((r) => (r.detail as { responseActionId?: string } | null)?.responseActionId)
      .filter(Boolean),
  );
  let found = 0;
  for (const a of actions) {
    if (reported.has(a.id) || (Array.isArray(a.approvals) && a.approvals.length > 0)) continue;
    let problem: string | null = null;
    if (!AI_INITIAL_CONTAINMENT.includes(a.actionType)) problem = `${ACTION_LABEL[a.actionType]} ran on its own, beyond the AI's initial containment`;
    else if (a.policyHash && a.tenantId && !(await db.orgPolicy.count({ where: { tenantId: a.tenantId, contentHash: a.policyHash, status: { in: ["ACTIVE", "SUPERSEDED"] } } }))) problem = "it was decided under rulebook text never approved for this client";
    if (!problem) continue;
    await reportViolation(a, problem);
    found++;
  }
  return found;
}
