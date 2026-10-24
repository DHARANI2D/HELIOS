import type { CaseSeverity, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { SEVERITY_ORDER } from "@/lib/severity";
import { serviceMetrics } from "@/lib/metrics";
import { coverageScore, missingEssentials, parseProtections, CONTROLS } from "@/lib/endpoints/controls";
import type { QuoteResult } from "@/lib/pricing/calculator";

// Everything the overview dashboards show, in one pass per role. Every query
// takes the viewer's case scope / tenant scope, so a client admin and a SOC
// manager running the same loader see their own worlds.

const DAY = 24 * 60 * 60 * 1000;
const TREND_DAYS = 14;

export async function loadOperationsDashboard(caseScope: Prisma.CaseWhereInput, tenantScope: { tenantId?: string | null }, viewerId: string) {
  const now = new Date();
  const since30 = new Date(now.getTime() - 30 * DAY);
  const trendStart = new Date(now.getTime() - (TREND_DAYS - 1) * DAY);
  trendStart.setUTCHours(0, 0, 0, 0);
  const open = { AND: [caseScope, { status: { notIn: CLOSED_STATUSES } }] } satisfies Prisma.CaseWhereInput;
  const soon = new Date(now.getTime() + 30 * 60_000);

  const [
    openCount,
    criticalOpen,
    slaDue,
    awaiting,
    unassignedCritical,
    severityGroups,
    trendRows,
    metrics,
    aiRuns30,
    aiAgree,
    aiDisagree,
    responseExecuted,
    aiTriagedCases,
    byTenant,
    byDomain,
    recent,
    mine,
    endpoints,
    integrations,
  ] = await Promise.all([
    db.case.count({ where: open }),
    db.case.count({ where: { AND: [open, { severity: "CRITICAL" }] } }),
    db.case.count({ where: { AND: [open, { acknowledgedAt: null, slaDueAt: { lte: soon } }] } }),
    db.case.count({ where: { AND: [open, { status: "AWAITING_APPROVAL" }] } }),
    db.case.count({ where: { AND: [open, { assignedToId: null, severity: { in: ["CRITICAL", "HIGH"] } }] } }),
    db.case.groupBy({ by: ["severity"], where: open, _count: { _all: true } }),
    db.case.findMany({ where: { AND: [caseScope, { createdAt: { gte: trendStart } }] }, select: { createdAt: true, severity: true } }),
    serviceMetrics(caseScope, since30, now),
    db.aiRun.count({ where: { createdAt: { gte: since30 }, case: caseScope } }),
    db.aiRun.count({ where: { createdAt: { gte: since30 }, case: caseScope, feedback: "agree" } }),
    db.aiRun.count({ where: { createdAt: { gte: since30 }, case: caseScope, feedback: "disagree" } }),
    db.responseAction.groupBy({ by: ["source"], where: { status: "EXECUTED", createdAt: { gte: since30 }, case: caseScope }, _count: { _all: true } }),
    db.case.findMany({
      where: { AND: [caseScope, { createdAt: { gte: since30 } }] },
      select: { aiStatus: true, responseActions: { where: { source: "ai", status: "EXECUTED" }, select: { id: true }, take: 1 } },
    }),
    db.case.groupBy({ by: ["tenantId"], where: open, _count: { _all: true } }),
    db.case.groupBy({ by: ["domain"], where: open, _count: { _all: true } }),
    db.case.findMany({
      where: caseScope,
      orderBy: { createdAt: "desc" },
      take: 8,
      select: { id: true, title: true, severity: true, status: true, sourceType: true, createdAt: true, slaDueAt: true, acknowledgedAt: true, aiStatus: true, tenant: { select: { name: true } } },
    }),
    db.case.findMany({
      where: { AND: [open, { assignedToId: viewerId }] },
      orderBy: [{ slaDueAt: { sort: "asc", nulls: "last" } }],
      take: 6,
      select: { id: true, title: true, severity: true, status: true, createdAt: true, slaDueAt: true, acknowledgedAt: true },
    }),
    db.endpoint.findMany({ where: tenantScope, select: { protections: true, isolated: true } }),
    db.integration.findMany({ where: { ...tenantScope }, select: { id: true, name: true, status: true, enabled: true, lastEventAt: true, tenant: { select: { name: true } } }, orderBy: { lastEventAt: { sort: "desc", nulls: "last" } }, take: 8 }),
  ]);

  const severityCounts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<CaseSeverity, number>;
  for (const g of severityGroups) severityCounts[g.severity] = g._count._all;

  const days = Array.from({ length: TREND_DAYS }, (_, i) => {
    const d = new Date(trendStart.getTime() + i * DAY);
    return { key: d.toISOString().slice(0, 10), label: d.toISOString().slice(5, 10), high: 0, other: 0 };
  });
  for (const r of trendRows) {
    const day = days.find((d) => d.key === r.createdAt.toISOString().slice(0, 10));
    if (!day) continue;
    if (r.severity === "CRITICAL" || r.severity === "HIGH") day.high++;
    else day.other++;
  }

  const autoContained = aiTriagedCases.filter((c) => c.responseActions.length > 0).length;
  const aiTriaged = aiTriagedCases.filter((c) => c.aiStatus === "completed").length - autoContained;
  const analystOnly = aiTriagedCases.length - autoContained - Math.max(0, aiTriaged);

  const tenantIds = byTenant.map((t) => t.tenantId).filter((x): x is string => !!x);
  const tenantNames = new Map((await db.tenant.findMany({ where: { id: { in: tenantIds } }, select: { id: true, name: true } })).map((t) => [t.id, t.name]));

  const parsed = endpoints.map((e) => parseProtections(e.protections));
  return {
    now,
    openCount,
    criticalOpen,
    slaDue,
    awaiting,
    unassignedCritical,
    severityCounts,
    trend: days,
    metrics,
    ai: {
      runs: aiRuns30,
      agreement: aiAgree + aiDisagree ? aiAgree / (aiAgree + aiDisagree) : null,
      autoExecuted: responseExecuted.find((r) => r.source === "ai")?._count._all ?? 0,
      firstResponse: { autoContained, aiTriaged: Math.max(0, aiTriaged), analystOnly: Math.max(0, analystOnly) },
    },
    byTenant: byTenant.map((t) => ({ name: t.tenantId ? tenantNames.get(t.tenantId) ?? "Unknown" : "Internal", count: t._count._all })).sort((a, b) => b.count - a.count).slice(0, 8),
    byDomain: byDomain.map((d) => ({ domain: d.domain, count: d._count._all })).sort((a, b) => b.count - a.count),
    recent,
    mine,
    endpoints: {
      total: endpoints.length,
      isolated: endpoints.filter((e) => e.isolated).length,
      avgScore: parsed.length ? Math.round(parsed.reduce((s, p) => s + coverageScore(p), 0) / parsed.length) : null,
      gaps: parsed.filter((p) => missingEssentials(p).length > 0).length,
      controls: CONTROLS.filter((c) => c.essential).map((c) => ({ label: c.label, pct: parsed.length ? Math.round((parsed.filter((p) => p[c.key]?.status === "active").length / parsed.length) * 100) : 0 })),
    },
    integrations,
  };
}

// Test clients and their quotes count only in a test environment.
export async function loadCommercialDashboard(includeTest: boolean) {
  const now = new Date();
  const real = includeTest ? {} : { isTest: false };
  const [tenants, quotes, testClients] = await Promise.all([
    db.tenant.findMany({ where: real, select: { id: true, name: true, status: true, plan: true, endpointsLicensed: true, usersLicensed: true } }),
    db.quote.findMany({ where: includeTest ? {} : { OR: [{ tenantId: null }, { tenant: real }] }, orderBy: { updatedAt: "desc" }, take: 200, select: { id: true, reference: true, clientName: true, status: true, currency: true, totals: true, updatedAt: true } }),
    includeTest ? Promise.resolve(0) : db.tenant.count({ where: { isTest: true } }),
  ]);
  const monthly = (q: (typeof quotes)[number]) => (q.totals as unknown as QuoteResult).monthlyNet ?? 0;
  const by = (status: string) => quotes.filter((q) => q.status === status);
  return {
    now,
    tenants,
    testClients,
    quotes: quotes.slice(0, 8),
    pipelineMonthly: by("SENT").reduce((s, q) => s + monthly(q), 0),
    wonMonthly: by("ACCEPTED").reduce((s, q) => s + monthly(q), 0),
    counts: { draft: by("DRAFT").length, sent: by("SENT").length, accepted: by("ACCEPTED").length, lost: by("LOST").length },
    winRate: by("ACCEPTED").length + by("LOST").length ? by("ACCEPTED").length / (by("ACCEPTED").length + by("LOST").length) : null,
  };
}
