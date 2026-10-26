import type { CaseDisposition, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { ACTION_LABEL } from "@/lib/response/labels";
import { RULED_ACTIONS } from "@/lib/rulebook/schema";
import { activeRulebook } from "@/lib/rulebook/service";
import { matchesAsset } from "@/lib/rulebook/evaluate";
import { DEMOTION, EMPTY_STATS, LEVELS, MAX_LEVEL, PROMOTION, demotionCheck, promotionCheck, scoreActions, scoreVerdict, type LadderStats } from "@/lib/shadow/ladder";

// Shadow mode on the server: each client's ladder, the decisions scored
// when a case closes, and the periodic review that proposes promotions (for
// the client to approve) and demotes automatically.

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

export async function setAutonomyLevel(tenantId: string, actionType: PlaybookActionType, level: number, actor: Actor, reason: string) {
  if (level < 0 || level > MAX_LEVEL) throw new Error("Unknown level");
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType } } });
  if (!row) throw new Error("Start shadow mode for this client first");
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
    ai.map((a) => ({ actionType: a.actionType, target: a.target, outcome: outcomeOf(a.trace, a.status), status: a.status, decidedById: a.decidedById, level: levelOf(a.parameters), critical: critical(a.target) })),
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
        await db.autonomyLevel.update({ where: { tenantId_actionType: { tenantId, actionType: row.actionType } }, data: { proposedLevel: row.level + 1, proposedAt: now, proposalStats: JSON.parse(JSON.stringify(stats)) } });
        await tell(tenantId, `Ready for more AI autonomy: ${ACTION_LABEL[row.actionType]} for ${tenant?.name}`, `${stats.agreed} of ${stats.decisions} AI decisions matched the analysts' in ${PROMOTION.windowDays} days, with no wrong containment of a critical asset. Approve the move to ${LEVELS[row.level + 1].name} on the rulebook page.`);
        changes++;
      }
    }
  }
  return changes;
}

// The client approves (or turns down) a proposed promotion. Staff can
// approve only on the client's recorded instruction.
export async function decidePromotion(tenantId: string, actionType: PlaybookActionType, approve: boolean, actor: Actor & { isClient: boolean }, note: string) {
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType } } });
  if (!row?.proposedLevel) throw new Error("No promotion is waiting for this action");
  if (approve && !actor.isClient && note.trim().length < 10) throw new Error("Record the client's instruction (who approved it, when and how)");
  await db.autonomyLevel.update({
    where: { tenantId_actionType: { tenantId, actionType } },
    data: approve
      ? { level: row.proposedLevel, reason: `Promoted on the shadow-mode record${actor.isClient ? "" : `; client's instruction: ${note.trim()}`}`, changedByName: actor.name, proposedLevel: null, proposedAt: null }
      : { proposedLevel: null, proposedAt: null },
  });
  await logAction({ actorId: actor.id, action: approve ? "autonomy.promoted" : "autonomy.promotion_declined", detail: { tenantId, actionType, from: row.level, to: approve ? row.proposedLevel : row.level, stats: row.proposalStats, note: note || null } });
}

export function dispositionLabel(d: CaseDisposition) {
  return d === "TRUE_POSITIVE" ? "True positive" : d === "BENIGN_TRUE_POSITIVE" ? "Benign true positive" : "False positive";
}
