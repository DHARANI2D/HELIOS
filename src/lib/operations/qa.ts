import type { ResponseActionStatus } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { notify, staffFor } from "@/lib/notifications";
import { ACTION_LABEL } from "@/lib/response/labels";
import { claimOnce, claimed } from "@/lib/jobs/once";
import { qaWeight, sampleSize, weekStart, weightedSample, type QaCandidate } from "@/lib/operations/qa-sample";

// Weekly QA of what the AI did without a person: each Monday, a weighted
// sample of last week's cases where it ran actions on its own or called a
// case benign goes to a reviewer other than the analyst who closed it. The
// reviewer says, per action, whether it should have run, and whether the
// verdict was right. Those calls feed the autonomy ladder's scoring, so a
// wrong action found in QA counts against the AI the same week.

const DAY = 86_400_000;
const AUTONOMOUS: ResponseActionStatus[] = ["EXECUTED", "ROLLED_BACK", "IN_PROGRESS", "FAILED"];
const VERDICT_AGENTS = ["triage", "phishing", "threat_intel", "investigator"];

// Actions the AI ran with nobody approving them.
export const autonomousWhere = (caseId?: string) => ({ ...(caseId ? { caseId } : {}), source: "ai", decidedById: null, status: { in: AUTONOMOUS } });

async function latestVerdict(caseId: string) {
  const run = await db.aiRun.findFirst({ where: { caseId, agentKey: { in: VERDICT_AGENTS }, status: { not: "failed" } }, orderBy: { createdAt: "desc" }, select: { output: true } });
  const v = (run?.output as { verdict?: string } | null)?.verdict;
  return v && v !== "needs_investigation" ? v : null;
}

export async function qaCandidates(from: Date, to: Date): Promise<QaCandidate[]> {
  const [actions, runs] = await Promise.all([
    db.responseAction.findMany({ where: { ...autonomousWhere(), createdAt: { gte: from, lt: to } }, select: { caseId: true, target: true, tenantId: true }, take: 20_000 }),
    db.aiRun.findMany({ where: { agentKey: { in: VERDICT_AGENTS }, status: { not: "failed" }, createdAt: { gte: from, lt: to } }, select: { caseId: true, output: true }, take: 20_000 }),
  ]);
  const benign = new Set(runs.filter((r) => r.caseId && (r.output as { verdict?: string } | null)?.verdict === "benign").map((r) => r.caseId!));
  const caseIds = [...new Set([...actions.map((a) => a.caseId), ...benign])];
  if (!caseIds.length) return [];
  const [cases, detections, critical] = await Promise.all([
    db.case.findMany({ where: { id: { in: caseIds } }, select: { id: true, tenantId: true, severity: true } }),
    db.detection.findMany({ where: { caseId: { in: caseIds }, source: "SIGMA_RULE" }, select: { caseId: true, ruleId: true } }),
    db.endpoint.findMany({ where: { criticality: "critical", hostname: { in: [...new Set(actions.map((a) => a.target ?? "").filter(Boolean))], mode: "insensitive" } }, select: { tenantId: true, hostname: true } }),
  ]);
  const newRules = new Set(
    (await db.detectionRule.findMany({ where: { sigmaId: { in: detections.map((d) => d.ruleId.replace(/^sigma:/, "")) }, createdAt: { gte: new Date(to.getTime() - 30 * DAY) } }, select: { sigmaId: true } })).map((r) => `sigma:${r.sigmaId}`),
  );
  const criticalKey = new Set(critical.map((e) => `${e.tenantId}|${e.hostname.toLowerCase()}`));
  return cases.map((c) => {
    const mine = actions.filter((a) => a.caseId === c.id);
    return {
      caseId: c.id,
      tenantId: c.tenantId,
      severity: c.severity,
      autonomousActions: mine.length,
      aiBenign: benign.has(c.id),
      newRule: detections.some((d) => d.caseId === c.id && newRules.has(d.ruleId)),
      criticalTarget: mine.some((a) => a.target && criticalKey.has(`${a.tenantId}|${a.target.toLowerCase()}`)),
    };
  });
}

export async function reviewers() {
  return staffFor(["SOC_MANAGER", "INCIDENT_RESPONDER"], null);
}

// Draws one week's sample (Monday to Monday), per client. Safe to repeat:
// the same week draws the same cases.
export async function sampleWeek(week: Date) {
  const from = weekStart(week);
  const to = new Date(from.getTime() + 7 * DAY);
  const { qaSharePct, qaMinPerClient } = await getSetting("operations");
  const candidates = await qaCandidates(from, to);
  const byTenant = new Map<string, QaCandidate[]>();
  for (const c of candidates) byTenant.set(c.tenantId ?? "", [...(byTenant.get(c.tenantId ?? "") ?? []), c]);
  const seed = from.toISOString().slice(0, 10);
  const picked = [...byTenant.entries()].flatMap(([tenant, cs]) => weightedSample(cs.map((c) => ({ ...c, ...qaWeight(c) })), sampleSize(cs.length, qaSharePct, qaMinPerClient), `${seed}|${tenant}`));
  if (!picked.length) return { population: candidates.length, sampled: 0, assigned: new Map<string, number>() };

  // Round-robin over reviewers, never the analyst who closed the case.
  const people = (await reviewers()).sort();
  const closers = new Map((await db.case.findMany({ where: { id: { in: picked.map((p) => p.caseId) } }, select: { id: true, dispositionById: true } })).map((c) => [c.id, c.dispositionById]));
  const assigned = new Map<string, number>();
  let turn = 0;
  const rows = picked
    .sort((a, b) => a.caseId.localeCompare(b.caseId))
    .map((p) => {
      let reviewerId: string | null = null;
      for (let i = 0; i < people.length; i++) {
        const candidate = people[(turn + i) % people.length];
        if (candidate !== closers.get(p.caseId)) {
          reviewerId = candidate;
          turn = (turn + i + 1) % people.length;
          break;
        }
      }
      if (reviewerId) assigned.set(reviewerId, (assigned.get(reviewerId) ?? 0) + 1);
      return { caseId: p.caseId, tenantId: p.tenantId, week: from, reasons: p.reasons, weight: p.weight, reviewerId };
    });
  const { count } = await db.qaReview.createMany({ data: rows, skipDuplicates: true });
  return { population: candidates.length, sampled: count, assigned };
}

// The job: last week's sample, once, early in the new week.
export async function runQaSampling(now = new Date()) {
  const last = new Date(weekStart(now).getTime() - 7 * DAY);
  const key = `qa.sampled:${last.toISOString().slice(0, 10)}`;
  if (await claimed(key)) return null;
  const result = await sampleWeek(last);
  if (!(await claimOnce(key))) return result;
  for (const [userId, n] of result.assigned) {
    await notify([userId], { kind: "qa", title: `${n} case${n === 1 ? "" : "s"} to review for AI quality`, body: `From the week of ${last.toISOString().slice(0, 10)}: what the AI did on its own, and the cases it called benign.`, href: "/operations#qa" });
  }
  if (result.sampled) await logAction({ action: "qa.sampled", detail: { week: last.toISOString().slice(0, 10), population: result.population, sampled: result.sampled } });
  return result;
}

export interface QaInput {
  // Per autonomous action: whether it should have run.
  actions: Record<string, "right" | "wrong">;
  // Whether the AI's verdict was right; null when it gave none.
  verdictRight: boolean | null;
  notes: string;
}

export async function submitQaReview(id: string, input: QaInput, user: { id: string; name: string }) {
  const review = await db.qaReview.findUniqueOrThrow({ where: { id }, include: { case: { select: { id: true, title: true, disposition: true, dispositionById: true } } } });
  if (review.status === "DONE") throw new Error("This case has already been reviewed");
  if (review.case.dispositionById === user.id) throw new Error("Someone other than the analyst who closed the case reviews it");
  const [actions, verdict] = await Promise.all([db.responseAction.findMany({ where: autonomousWhere(review.caseId) }), latestVerdict(review.caseId)]);
  for (const a of actions) if (!input.actions[a.id]) throw new Error("Say for each action the AI ran whether it should have");
  if (verdict && input.verdictRight == null) throw new Error("Say whether the AI's verdict was right");
  const calls = [...actions.map((a) => input.actions[a.id] === "right"), ...(verdict ? [!!input.verdictRight] : [])];
  const outcome = calls.every(Boolean) ? "agree" : calls.some(Boolean) ? "partly" : "disagree";
  const wrong = actions.filter((a) => input.actions[a.id] === "wrong");
  const now = new Date();
  await db.$transaction([
    ...actions.map((a) => db.responseAction.update({ where: { id: a.id }, data: { qaVerdict: input.actions[a.id] } })),
    db.qaReview.update({ where: { id }, data: { status: "DONE", outcome, verdictRight: verdict ? input.verdictRight : null, notes: input.notes.trim().slice(0, 4000) || null, reviewedById: user.id, reviewedBy: user.name, reviewedAt: now } }),
    db.timelineEntry.create({ data: { caseId: review.caseId, occurredAt: now, actor: user.name, action: "qa.reviewed", detail: `QA review: ${outcome === "agree" ? "the AI got it right" : outcome === "partly" ? "the AI got it partly right" : "the AI got it wrong"}${wrong.length ? `; shouldn't have run: ${wrong.map((a) => `${ACTION_LABEL[a.actionType]} ${a.target ?? ""}`.trim()).join(", ")}` : ""}` } }),
  ]);
  await logAction({ actorId: user.id, caseId: review.caseId, action: "qa.reviewed", detail: { reviewId: id, outcome, wrongActions: wrong.map((a) => a.id), verdictRight: input.verdictRight } });
  // Re-score a closed case with the reviewer's calls, and let the ladder
  // react now rather than at the next hourly review.
  if (review.case.disposition) {
    const { scoreClosedCase, reviewLadders } = await import("@/lib/shadow/service");
    await scoreClosedCase(review.caseId);
    if (wrong.length) await reviewLadders(now);
  }
  if (wrong.length || (verdict && input.verdictRight === false)) {
    await notify(await staffFor(["SOC_MANAGER"], null), {
      kind: "qa",
      title: `QA: the AI got "${review.case.title}" ${outcome === "disagree" ? "wrong" : "partly wrong"}`,
      body: [wrong.length ? `Shouldn't have run: ${wrong.map((a) => `${ACTION_LABEL[a.actionType]} ${a.target ?? ""}`.trim()).join(", ")}` : "", verdict && input.verdictRight === false ? `Verdict "${verdict.replace("_", " ")}" was wrong` : "", input.notes.trim()].filter(Boolean).join(". "),
      caseId: review.caseId,
      actorName: user.name,
    }, { exclude: user.id });
  }
  return outcome;
}

// The review form's facts for a case: its autonomous actions and the verdict.
export async function qaContext(caseId: string) {
  const [review, actions, verdict] = await Promise.all([
    db.qaReview.findFirst({ where: { caseId }, orderBy: { week: "desc" } }),
    db.responseAction.findMany({ where: autonomousWhere(caseId), orderBy: { createdAt: "asc" }, select: { id: true, actionType: true, target: true, status: true, parameters: true, qaVerdict: true, createdAt: true } }),
    latestVerdict(caseId),
  ]);
  return review ? { review, actions, verdict } : null;
}

export async function qaStats(weeks = 6, now = new Date()) {
  const since = new Date(weekStart(now).getTime() - (weeks - 1) * 7 * DAY);
  const rows = await db.qaReview.findMany({ where: { week: { gte: since } }, select: { week: true, status: true, outcome: true } });
  const wrong = await db.responseAction.groupBy({ by: ["actionType"], where: { qaVerdict: "wrong", createdAt: { gte: since } }, _count: true });
  const byWeek = new Map<string, { sampled: number; reviewed: number; agree: number; partly: number; disagree: number }>();
  for (const r of rows) {
    const k = r.week.toISOString().slice(0, 10);
    const w = byWeek.get(k) ?? { sampled: 0, reviewed: 0, agree: 0, partly: 0, disagree: 0 };
    w.sampled++;
    if (r.status === "DONE") {
      w.reviewed++;
      if (r.outcome === "agree" || r.outcome === "partly" || r.outcome === "disagree") w[r.outcome]++;
    }
    byWeek.set(k, w);
  }
  return { weeks: [...byWeek.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([week, w]) => ({ week, ...w })), wrongByAction: wrong.map((w) => ({ actionType: w.actionType, count: w._count })) };
}
