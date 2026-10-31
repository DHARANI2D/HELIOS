import type { CaseDisposition, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { ACTION_LABEL } from "@/lib/response/labels";
import { RULED_ACTIONS } from "@/lib/rulebook/schema";
import { activeRulebook } from "@/lib/rulebook/service";
import { matchesAsset } from "@/lib/rulebook/evaluate";
import { DEMOTION, EMPTY_STATS, LEVELS, MAX_LEVEL, PROMOTION, demotionCheck, promotionCheck, scoreActions, scoreVerdict, type LadderStats } from "@/lib/shadow/ladder";
import { AUTOMATIC_REVIEW, approveChange, rejectChange, requestChange, type ChangeActor } from "@/lib/changes/service";

// Shadow mode on the server: each client's ladder, the decisions scored
// when a case closes, and the periodic review that proposes promotions and
// demotes automatically. A promotion is a rule change: it takes effect only
// once the client and HELIOS have approved it (lib/changes). A demotion only
// takes power away from the AI, so it applies at once.

export interface Actor {
  id: string;
  name: string;
}

// The client's ladder, or null when it hasn't been started (then the
// ladder doesn't restrict anything; plan, consent and rulebook still do).
export async function ladderFor(tenantId: string | null | undefined): Promise<Map<PlaybookActionType, number> | null> {
  if (!tenantId) return null;
  const rows = await db.autonomyLevel.findMany({ where: { tenantId } });
  return rows.length ? new Map(rows.map((r) => [r.actionType, r.level])) : null;
}

// Every ruled action at level 0: the AI only observes, and its analysis
// stays out of sight until the case closes.
export function observing(ladder: Map<PlaybookActionType, number> | null) {
  return !!ladder && [...ladder.values()].every((l) => l === 0);
}

export async function startShadowMode(tenantId: string, actor: Actor) {
  await db.$transaction(
    RULED_ACTIONS.map((actionType) =>
      db.autonomyLevel.upsert({
        where: { tenantId_actionType: { tenantId, actionType } },
        update: {},
        create: { tenantId, actionType, level: 0, changedByName: actor.name, reason: "Shadow mode started" },
      }),
    ),
  );
  await logAction({ actorId: actor.id, action: "autonomy.shadow_started", detail: { tenantId } });
}

// Lowers a level at once. Raising one goes through proposePromotion.
export async function setAutonomyLevel(tenantId: string, actionType: PlaybookActionType, level: number, actor: Actor, reason: string) {
  if (level < 0 || level > MAX_LEVEL) throw new Error("Unknown level");
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType } } });
  if (!row) throw new Error("Start shadow mode for this client first");
  if (level > row.level) throw new Error("Raising a level needs the client's and HELIOS's approval: propose a promotion");
  await db.autonomyLevel.update({ where: { tenantId_actionType: { tenantId, actionType } }, data: { level, reason, changedByName: actor.name, proposedLevel: null, proposedAt: null, proposalStats: undefined } });
  await logAction({ actorId: actor.id, action: "autonomy.level_changed", detail: { tenantId, actionType, from: row.level, to: level, reason } });
}

// ---------------------------------------------------------------- scoring

export async function scoreClosedCase(caseId: string) {
  const kase = await db.case.findUniqueOrThrow({
    where: { id: caseId },
    select: { id: true, tenantId: true, severity: true, disposition: true, responseActions: true, aiRuns: { where: { agentKey: { in: ["triage", "phishing", "threat_intel", "investigator"] }, status: { not: "failed" } }, orderBy: { createdAt: "desc" }, take: 1 } },
  });
  await db.aiDecisionOutcome.deleteMany({ where: { caseId } });
  if (!kase.disposition) return 0;

  const rb = await activeRulebook(kase.tenantId);
  const endpoints = kase.tenantId
    ? await db.endpoint.findMany({ where: { tenantId: kase.tenantId, hostname: { in: kase.responseActions.map((a) => a.target ?? "").filter(Boolean), mode: "insensitive" } }, select: { hostname: true, criticality: true, assetType: true, assetClass: true } })
    : [];
  const critical = (target: string | null) => {
    if (!target) return false;
    const e = endpoints.find((x) => x.hostname.toLowerCase() === target.toLowerCase());
    if (e?.criticality === "critical") return true;
    const facts = { hostname: target, assetType: e?.assetType, assetGroup: e?.assetClass, criticality: e?.criticality };
    return !!rb && [...rb.body.assets.crownJewels, ...rb.body.assets.neverIsolate].some((m) => matchesAsset(m, facts, target));
  };
  const outcomeOf = (trace: unknown, status: string) => {
    const first = Array.isArray(trace) ? (trace[0] as { outcome?: string } | undefined) : undefined;
    return first?.outcome ?? (status === "SHADOW" ? "SUGGESTED" : status === "EXECUTED" ? "EXECUTED" : status === "SUGGESTED" ? "SUGGESTED" : status === "BLOCKED" ? "BLOCKED" : "PENDING_APPROVAL");
  };
  const levelOf = (parameters: unknown) => {
    const v = parameters && typeof parameters === "object" ? (parameters as { ladderLevel?: unknown }).ladderLevel : undefined;
    return typeof v === "number" ? v : typeof v === "string" ? Number(v) : null;
  };

  // Rollbacks undo an action rather than being one.
  const isRollback = (parameters: unknown) => !!parameters && typeof parameters === "object" && "rollbackOf" in parameters;
  const ai = kase.responseActions.filter((a) => a.source === "ai");
  const human = kase.responseActions.filter((a) => a.source === "analyst" && !isRollback(a.parameters));
  const scored = scoreActions(
    ai.map((a) => ({ actionType: a.actionType, target: a.target, outcome: outcomeOf(a.trace, a.status), status: a.status, decidedById: a.decidedById, level: levelOf(a.parameters), critical: critical(a.target), qa: a.qaVerdict })),
    human.map((h) => ({ actionType: h.actionType, target: h.target, status: h.status })),
    kase.disposition,
  );
  const verdict = (kase.aiRuns[0]?.output as { verdict?: string } | null)?.verdict;
  const v = scoreVerdict(verdict, kase.disposition);
  const rows = [
    ...scored.map((s) => ({ ...s, actionType: s.actionType as PlaybookActionType, tenantId: kase.tenantId, caseId, severity: kase.severity })),
    ...(v ? [{ kind: "verdict", tenantId: kase.tenantId, caseId, severity: kase.severity, aiOutcome: verdict!, humanOutcome: kase.disposition, agreed: v.agreed, falseContainment: false, critical: false }] : []),
  ];
  if (rows.length) await db.aiDecisionOutcome.createMany({ data: rows });
  return rows.length;
}

// ---------------------------------------------------------------- stats

export async function ladderStats(tenantId: string, since: Date) {
  const rows = await db.aiDecisionOutcome.findMany({ where: { tenantId, createdAt: { gte: since } }, select: { kind: true, actionType: true, aiOutcome: true, agreed: true, falseContainment: true, critical: true } });
  const byAction = new Map<PlaybookActionType, LadderStats>();
  const verdicts = { scored: 0, agreed: 0 };
  for (const r of rows) {
    if (r.kind === "verdict") {
      verdicts.scored++;
      if (r.agreed) verdicts.agreed++;
      continue;
    }
    if (!r.actionType) continue;
    const s = { ...(byAction.get(r.actionType) ?? EMPTY_STATS) };
    if (r.aiOutcome === "NONE") s.misses++;
    else {
      s.decisions++;
      if (r.agreed) s.agreed++;
      if (r.falseContainment) s.falseContainments++;
      if (r.falseContainment && r.critical) s.criticalFalseContainments++;
    }
    byAction.set(r.actionType, s);
  }
  return { byAction, verdicts };
}

// ---------------------------------------------------------------- review

async function tell(tenantId: string, title: string, body: string) {
  const admins = await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  await notify([...(await staffFor(["SOC_MANAGER"], null)), ...admins.map((a) => a.id)], { kind: "ai", title, body, href: `/rulebook?tenant=${tenantId}` });
}

// Demote on a bad week; propose a promotion (the client approves it) once
// the record supports one. Safe to run repeatedly.
export async function reviewLadders(now = new Date()) {
  const tenants = await db.autonomyLevel.findMany({ distinct: ["tenantId"], select: { tenantId: true } });
  let changes = 0;
  for (const { tenantId } of tenants) {
    const [rows, week, month, tenant] = await Promise.all([
      db.autonomyLevel.findMany({ where: { tenantId } }),
      ladderStats(tenantId, new Date(now.getTime() - DEMOTION.windowDays * 86_400_000)),
      ladderStats(tenantId, new Date(now.getTime() - PROMOTION.windowDays * 86_400_000)),
      db.tenant.findUnique({ where: { id: tenantId }, select: { name: true } }),
    ]);
    for (const row of rows) {
      const d = demotionCheck(row.level, week.byAction.get(row.actionType) ?? EMPTY_STATS);
      if (d.demote) {
        await db.autonomyLevel.update({ where: { tenantId_actionType: { tenantId, actionType: row.actionType } }, data: { level: d.to, reason: d.reason, changedByName: "automatic review", proposedLevel: null, proposedAt: null } });
        await logAction({ action: "autonomy.demoted", detail: { tenantId, actionType: row.actionType, from: row.level, to: d.to, reason: d.reason } });
        await tell(tenantId, `AI autonomy lowered for ${tenant?.name}: ${ACTION_LABEL[row.actionType]}`, `${LEVELS[row.level].name} → ${LEVELS[d.to].name}. ${d.reason}`);
        changes++;
        continue;
      }
      const stats = month.byAction.get(row.actionType) ?? EMPTY_STATS;
      const p = promotionCheck(row.level, stats);
      if (p.eligible && row.proposedLevel == null) {
        await proposePromotion(tenantId, row.actionType, row.level, stats, AUTOMATIC_REVIEW, now);
        changes++;
      }
    }
  }
  return changes;
}

// Proposes the next level for one action, on its shadow-mode record. HELIOS's
// review does it automatically; staff can do it once the record supports it.
export async function proposePromotion(tenantId: string, actionType: PlaybookActionType, from: number, stats: LadderStats, actor: ChangeActor | typeof AUTOMATIC_REVIEW, now = new Date()) {
  if (from >= MAX_LEVEL) throw new Error("Already at the top level");
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { name: true } });
  const to = from + 1;
  await db.autonomyLevel.update({ where: { tenantId_actionType: { tenantId, actionType } }, data: { proposedLevel: to, proposedAt: now, proposalStats: JSON.parse(JSON.stringify(stats)) } });
  return requestChange(
    {
      tenantId,
      kind: "AUTONOMY_RAISE",
      summary: `${ACTION_LABEL[actionType]} for ${tenant?.name ?? "the client"}: ${LEVELS[from].name} → ${LEVELS[to].name}`,
      reason: `${stats.agreed} of ${stats.decisions} AI decisions matched the analysts' in ${PROMOTION.windowDays} days, with no wrong containment of a critical asset`,
      payload: { actionType, from, to, stats },
    },
    actor,
  );
}

// One side's decision on a proposed promotion: approving it (the client's
// admin, or staff recording the client's instruction, and a HELIOS approver)
// or turning it down.
export async function decidePromotion(tenantId: string, actionType: PlaybookActionType, approve: boolean, actor: ChangeActor, note: string, side: "client" | "helios" = actor.isClient ? "client" : "helios") {
  const change = (await db.ruleChange.findMany({ where: { tenantId, kind: "AUTONOMY_RAISE", status: "PENDING" }, orderBy: { createdAt: "desc" } })).find((c) => (c.payload as { actionType?: string }).actionType === actionType);
  if (!change) throw new Error("No promotion is waiting for this action");
  if (!approve) return rejectChange(change.id, actor, note || "Declined");
  return approveChange(change.id, side, actor, note);
}

export function dispositionLabel(d: CaseDisposition) {
  return d === "TRUE_POSITIVE" ? "True positive" : d === "BENIGN_TRUE_POSITIVE" ? "Benign true positive" : "False positive";
}
