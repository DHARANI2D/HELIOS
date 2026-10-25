import type { CaseSeverity, CaseSource, CaseStatus, Prisma, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { CLOSED_STATUSES } from "@/lib/cases/labels";

// Service reporting: what the SOC handled in a period, how fast, and how it
// held to the clients' SLAs. Everything is computed from case, AI-run and
// response-action rows — no estimates. The pure half (summarizeCases) is
// unit-tested; loadServiceReport fetches and assembles.

export interface ReportRange {
  key: string; // "30d", "2026-10", …
  label: string;
  from: Date;
  to: Date; // exclusive
}

const PRESETS: Record<string, number> = { "7d": 7, "30d": 30, "90d": 90, "365d": 365 };
const DAY = 86_400_000;

export function parseRange(params: { range?: string; month?: string }, now = new Date()): ReportRange {
  const month = params.month?.match(/^(\d{4})-(\d{2})$/);
  if (month) {
    const from = new Date(Date.UTC(Number(month[1]), Number(month[2]) - 1, 1));
    const to = new Date(Date.UTC(Number(month[1]), Number(month[2]), 1));
    if (!Number.isNaN(from.getTime()) && from < now) {
      return { key: params.month!, label: from.toLocaleDateString("en-US", { month: "long", year: "numeric", timeZone: "UTC" }), from, to };
    }
  }
  const key = params.range && PRESETS[params.range] ? params.range : "30d";
  return { key, label: `Last ${PRESETS[key]} days`, from: new Date(now.getTime() - PRESETS[key] * DAY), to: now };
}

export function previousRange(r: ReportRange): ReportRange {
  const len = r.to.getTime() - r.from.getTime();
  return { key: `prev-${r.key}`, label: "Previous period", from: new Date(r.from.getTime() - len), to: r.from };
}

export interface CaseFacts {
  createdAt: Date;
  acknowledgedAt: Date | null;
  containedAt: Date | null;
  resolvedAt: Date | null;
  slaDueAt: Date | null;
  severity: CaseSeverity;
  status: CaseStatus;
  sourceType: CaseSource;
  domain: SecurityDomain | null;
  tenantId: string | null;
  assignedToId: string | null;
}

export function median(values: number[]): number | null {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

const inRange = (d: Date | null, r: ReportRange) => !!d && d >= r.from && d < r.to;

export interface SlaOutcome {
  met: number;
  breached: number;
  pending: number;
  compliance: number | null; // met / (met + breached)
}

// The acknowledge-by SLA of every case opened in the range that had one.
export function slaOutcome(cases: CaseFacts[], now: Date): SlaOutcome {
  let met = 0;
  let breached = 0;
  let pending = 0;
  for (const c of cases) {
    if (!c.slaDueAt) continue;
    if (c.acknowledgedAt) {
      if (c.acknowledgedAt <= c.slaDueAt) met++;
      else breached++;
    } else if (now > c.slaDueAt) breached++;
    else pending++;
  }
  return { met, breached, pending, compliance: met + breached ? met / (met + breached) : null };
}

export interface CaseSummary {
  opened: number;
  closed: number;
  falsePositives: number;
  medianAcknowledgeMs: number | null;
  medianContainMs: number | null;
  medianResolveMs: number | null;
  sla: SlaOutcome;
  bySeverity: Partial<Record<CaseSeverity, number>>;
  bySource: Partial<Record<CaseSource, number>>;
  byDomain: Partial<Record<SecurityDomain | "UNASSIGNED", number>>;
  byTenant: Record<string, number>;
}

function countBy<T extends string>(items: T[]): Partial<Record<T, number>> {
  const out: Partial<Record<T, number>> = {};
  for (const i of items) out[i] = (out[i] ?? 0) + 1;
  return out;
}

// `opened` are the cases created in the range, `closed` those resolved in it
// (whenever they were opened).
export function summarizeCases(opened: CaseFacts[], closed: CaseFacts[], range: ReportRange, now: Date): CaseSummary {
  const ms = (a: Date | null, b: Date) => (a ? a.getTime() - b.getTime() : null);
  const nums = (xs: Array<number | null>) => xs.filter((x): x is number => x !== null && x >= 0);
  return {
    opened: opened.length,
    closed: closed.length,
    falsePositives: closed.filter((c) => c.status === "FALSE_POSITIVE").length,
    medianAcknowledgeMs: median(nums(opened.map((c) => ms(c.acknowledgedAt, c.createdAt)))),
    medianContainMs: median(nums(opened.filter((c) => inRange(c.containedAt, range)).map((c) => ms(c.containedAt, c.createdAt)))),
    medianResolveMs: median(nums(closed.map((c) => ms(c.resolvedAt, c.createdAt)))),
    sla: slaOutcome(opened, now),
    bySeverity: countBy(opened.map((c) => c.severity)),
    bySource: countBy(opened.map((c) => c.sourceType)),
    byDomain: countBy(opened.map((c) => c.domain ?? "UNASSIGNED")),
    byTenant: countBy(opened.map((c) => c.tenantId ?? "internal")) as Record<string, number>,
  };
}

export interface TrendPoint {
  label: string;
  start: string;
  opened: number;
  closed: number;
}

// Daily buckets up to two months, weekly (Monday, UTC) beyond.
export function caseTrend(opened: CaseFacts[], closed: CaseFacts[], range: ReportRange): TrendPoint[] {
  const span = range.to.getTime() - range.from.getTime();
  const weekly = span > 62 * DAY;
  const startOf = (d: Date) => {
    const day = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    if (weekly) day.setUTCDate(day.getUTCDate() - ((day.getUTCDay() + 6) % 7));
    return day.getTime();
  };
  const step = weekly ? 7 * DAY : DAY;
  const points = new Map<number, TrendPoint>();
  for (let t = startOf(range.from); t < range.to.getTime(); t += step) {
    const d = new Date(t);
    points.set(t, { start: d.toISOString().slice(0, 10), label: d.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" }), opened: 0, closed: 0 });
  }
  for (const c of opened) {
    const p = points.get(startOf(c.createdAt));
    if (p) p.opened++;
  }
  for (const c of closed) {
    const p = c.resolvedAt && points.get(startOf(c.resolvedAt));
    if (p) p.closed++;
  }
  return [...points.values()];
}

const FACTS = {
  createdAt: true,
  acknowledgedAt: true,
  containedAt: true,
  resolvedAt: true,
  slaDueAt: true,
  severity: true,
  status: true,
  sourceType: true,
  domain: true,
  tenantId: true,
  assignedToId: true,
} satisfies Prisma.CaseSelect;

async function caseFacts(scope: Prisma.CaseWhereInput, r: ReportRange) {
  const [opened, closed] = await Promise.all([
    db.case.findMany({ where: { AND: [scope, { createdAt: { gte: r.from, lt: r.to } }] }, select: FACTS }),
    db.case.findMany({ where: { AND: [scope, { resolvedAt: { gte: r.from, lt: r.to } }, { status: { in: [...CLOSED_STATUSES] } }] }, select: FACTS }),
  ]);
  return { opened, closed };
}

export interface AnalystRow {
  id: string;
  name: string;
  openAssigned: number;
  closed: number;
  medianResolveMs: number | null;
}

export async function loadServiceReport(scope: Prisma.CaseWhereInput, range: ReportRange, now = new Date()) {
  const prev = previousRange(range);
  const window = { gte: range.from, lt: range.to };
  const [current, before, openNow, techniques, indicators, aiRuns, actions] = await Promise.all([
    caseFacts(scope, range),
    caseFacts(scope, prev),
    db.case.count({ where: { AND: [scope, { status: { notIn: [...CLOSED_STATUSES] } }] } }),
    db.caseMitreTechnique.groupBy({ by: ["techniqueId"], where: { case: { AND: [scope, { createdAt: window }] } }, _count: { _all: true }, orderBy: { _count: { techniqueId: "desc" } }, take: 10 }),
    db.caseIndicator.findMany({
      where: { case: { AND: [scope, { createdAt: window }] }, indicator: { maliciousScore: { gte: 0.7 } } },
      select: { caseId: true, indicator: { select: { type: true, value: true, maliciousScore: true } } },
      take: 2000,
    }),
    db.aiRun.findMany({ where: { createdAt: window, case: scope }, select: { status: true, feedback: true, durationMs: true, trigger: true, isLocal: true } }),
    db.responseAction.findMany({ where: { createdAt: window, case: scope, status: { not: "SHADOW" } }, select: { actionType: true, status: true, source: true } }),
  ]);

  const summary = summarizeCases(current.opened, current.closed, range, now);
  const previous = summarizeCases(before.opened, before.closed, prev, range.from);

  const techniqueNames = new Map(
    (await db.mitreTechnique.findMany({ where: { id: { in: techniques.map((t) => t.techniqueId) } }, select: { id: true, name: true } })).map((t) => [t.id, t.name]),
  );
  const indicatorCases = new Map<string, { type: string; value: string; score: number; cases: Set<string> }>();
  for (const ci of indicators) {
    const key = `${ci.indicator.type}:${ci.indicator.value}`;
    const entry = indicatorCases.get(key) ?? { type: ci.indicator.type, value: ci.indicator.value, score: ci.indicator.maliciousScore ?? 0, cases: new Set<string>() };
    entry.cases.add(ci.caseId);
    indicatorCases.set(key, entry);
  }

  const tenantIds = Object.keys(summary.byTenant).filter((t) => t !== "internal");
  const tenants = new Map((await db.tenant.findMany({ where: { id: { in: tenantIds } }, select: { id: true, name: true, isTest: true } })).map((t) => [t.id, t]));

  const assignees = [...new Set([...current.closed, ...current.opened].map((c) => c.assignedToId).filter((x): x is string => !!x))];
  const [users, openAssigned] = await Promise.all([
    db.user.findMany({ where: { id: { in: assignees } }, select: { id: true, name: true, email: true } }),
    db.case.groupBy({ by: ["assignedToId"], where: { AND: [scope, { assignedToId: { in: assignees } }, { status: { notIn: [...CLOSED_STATUSES] } }] }, _count: { _all: true } }),
  ]);
  const openBy = new Map(openAssigned.map((o) => [o.assignedToId, o._count._all]));
  const analysts: AnalystRow[] = users
    .map((u) => {
      const theirs = current.closed.filter((c) => c.assignedToId === u.id);
      return {
        id: u.id,
        name: u.name ?? u.email,
        openAssigned: openBy.get(u.id) ?? 0,
        closed: theirs.length,
        medianResolveMs: median(theirs.map((c) => c.resolvedAt!.getTime() - c.createdAt.getTime()).filter((x) => x >= 0)),
      };
    })
    .sort((a, b) => b.closed - a.closed || b.openAssigned - a.openAssigned);

  const rated = aiRuns.filter((r) => r.feedback);
  return {
    range,
    previous: prev,
    generatedAt: now,
    openNow,
    summary,
    previousSummary: previous,
    trend: caseTrend(current.opened, current.closed, range),
    tenants: Object.entries(summary.byTenant)
      .map(([id, count]) => ({ id, name: id === "internal" ? "Internal" : tenants.get(id)?.name ?? "Unknown", isTest: tenants.get(id)?.isTest ?? false, count }))
      .sort((a, b) => b.count - a.count),
    techniques: techniques.map((t) => ({ id: t.techniqueId, name: techniqueNames.get(t.techniqueId) ?? t.techniqueId, count: t._count._all })),
    indicators: [...indicatorCases.values()].map((i) => ({ type: i.type, value: i.value, score: i.score, cases: i.cases.size })).sort((a, b) => b.cases - a.cases || b.score - a.score).slice(0, 10),
    analysts,
    ai: {
      runs: aiRuns.length,
      automatic: aiRuns.filter((r) => r.trigger === "auto").length,
      local: aiRuns.filter((r) => r.isLocal).length,
      byStatus: countBy(aiRuns.map((r) => r.status)),
      medianDurationMs: median(aiRuns.map((r) => r.durationMs).filter((x): x is number => x != null)),
      rated: rated.length,
      agreed: rated.filter((r) => r.feedback === "agree").length,
    },
    actions: {
      total: actions.length,
      byStatus: countBy(actions.map((a) => a.status)),
      byType: countBy(actions.map((a) => a.actionType)),
      fromAi: actions.filter((a) => a.source === "ai").length,
    },
  };
}

export type ServiceReport = Awaited<ReturnType<typeof loadServiceReport>>;

export function formatDuration(ms: number | null): string {
  if (ms == null) return "—";
  const m = ms / 60_000;
  if (m < 1) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (m < 90) return `${Math.round(m)}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(h < 10 ? 1 : 0)}h`;
  return `${(h / 24).toFixed(1)}d`;
}
