import { z } from "zod";
import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { caseVisibility, canAccessCase } from "@/lib/access";
import { can } from "@/lib/rbac";
import { CASE_STATUSES, CLOSED_STATUSES } from "@/lib/cases/labels";
import { setCaseSeverity, setCaseStatus } from "@/lib/cases/service";
import { addComment, assignCaseTo } from "@/lib/cases/collab";
import { classifyIndicator } from "@/lib/threat-intel/indicators";
import { indicatorReasons, indicatorVerdict, lookupIndicator } from "@/lib/threat-intel/service";
import { loadServiceReport, parseRange } from "@/lib/reports";
import { ApiError } from "@/lib/api/http";
import type { ApiPrincipal } from "@/lib/api/tokens";

// REST API v1 — the successor of signal-fusion's Express API, for ticketing
// systems, SOAR and client portals. Everything goes through the same
// visibility rules and permission checks as the app; out-of-scope cases
// read as not found.

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const SOURCES = ["AGENT_GOVERNANCE", "SOC_INVESTIGATION", "EMAIL_ANALYSIS", "SIEM_ALERT"] as const;

const listSchema = z.object({
  status: z.union([z.enum(["open", "closed", "all"]), z.enum(CASE_STATUSES as [string, ...string[]])]).default("open"),
  severity: z.enum(SEVERITIES).optional(),
  source: z.enum(SOURCES).optional(),
  tenantId: z.string().optional(),
  since: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  cursor: z.string().optional(),
});

function caseSummary(c: Prisma.CaseGetPayload<{ include: { tenant: { select: { id: true; name: true } }; assignedTo: { select: { email: true; name: true } } } }>) {
  return {
    id: c.id,
    title: c.title,
    summary: c.summary,
    source: c.sourceType,
    severity: c.severity,
    status: c.status,
    verdict: c.verdict,
    confidence: c.confidence,
    riskScore: c.riskScore,
    domain: c.domain,
    tier: c.tier,
    client: c.tenant ? { id: c.tenant.id, name: c.tenant.name } : null,
    assignee: c.assignedTo ? { email: c.assignedTo.email, name: c.assignedTo.name } : null,
    createdAt: c.createdAt,
    acknowledgedAt: c.acknowledgedAt,
    containedAt: c.containedAt,
    resolvedAt: c.resolvedAt,
    slaDueAt: c.slaDueAt,
  };
}

const SUMMARY_INCLUDE = { tenant: { select: { id: true, name: true } }, assignedTo: { select: { email: true, name: true } } } as const;

export async function listCases(p: ApiPrincipal, params: URLSearchParams) {
  const q = listSchema.parse(Object.fromEntries(params));
  const filters: Prisma.CaseWhereInput[] = [caseVisibility(p)];
  if (q.status === "open") filters.push({ status: { notIn: CLOSED_STATUSES } });
  else if (q.status === "closed") filters.push({ status: { in: CLOSED_STATUSES } });
  else if (q.status !== "all") filters.push({ status: q.status as (typeof CASE_STATUSES)[number] });
  if (q.severity) filters.push({ severity: q.severity });
  if (q.source) filters.push({ sourceType: q.source });
  if (q.tenantId && !p.isClient) filters.push({ tenantId: q.tenantId });
  if (q.since) filters.push({ createdAt: { gte: q.since } });
  const rows = await db.case.findMany({
    where: { AND: filters },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: q.limit + 1,
    ...(q.cursor ? { cursor: { id: q.cursor }, skip: 1 } : {}),
    include: SUMMARY_INCLUDE,
  });
  const page = rows.slice(0, q.limit);
  return { data: page.map(caseSummary), nextCursor: rows.length > q.limit ? page[page.length - 1].id : null };
}

async function visibleCase(p: ApiPrincipal, id: string) {
  if (!(await canAccessCase(p, id))) throw new ApiError(404, "Case not found");
}

export async function getCase(p: ApiPrincipal, id: string) {
  await visibleCase(p, id);
  const c = await db.case.findUniqueOrThrow({
    where: { id },
    include: {
      ...SUMMARY_INCLUDE,
      detections: { orderBy: { createdAt: "asc" }, select: { source: true, ruleId: true, title: true, severity: true, createdAt: true } },
      indicators: { select: { role: true, indicator: { select: { type: true, value: true, maliciousScore: true, blockedAt: true } } } },
      mitreTechniques: { select: { technique: { select: { id: true, name: true, tacticId: true } } } },
      timeline: { orderBy: [{ occurredAt: "desc" }], take: 100, select: { occurredAt: true, actor: true, action: true, detail: true } },
      responseActions: { orderBy: { createdAt: "asc" }, select: { id: true, actionType: true, target: true, status: true, source: true, createdAt: true, decidedAt: true } },
      comments: { where: p.isClient ? { internal: false } : {}, orderBy: { createdAt: "asc" }, select: { id: true, authorName: true, body: true, internal: true, createdAt: true } },
    },
  });
  return {
    ...caseSummary(c),
    rootCause: c.rootCauseNarrative,
    detections: c.detections,
    indicators: c.indicators.map((i) => ({ type: i.indicator.type, value: i.indicator.value, role: i.role, reputation: i.indicator.maliciousScore, blocked: !!i.indicator.blockedAt })),
    techniques: c.mitreTechniques.map((m) => m.technique),
    timeline: c.timeline,
    responseActions: c.responseActions,
    comments: c.comments,
  };
}

const updateSchema = z
  .object({
    status: z.enum(CASE_STATUSES as [string, ...string[]]).optional(),
    severity: z.enum(SEVERITIES).optional(),
    // Email of the analyst to assign, or null to unassign.
    assignee: z.string().email().nullable().optional(),
    note: z.string().trim().max(2000).optional(),
  })
  .strict()
  .refine((u) => u.status || u.severity || u.assignee !== undefined, { message: "Nothing to change" });

export async function updateCase(p: ApiPrincipal, id: string, body: unknown) {
  await visibleCase(p, id);
  const u = updateSchema.parse(body);
  if ((u.status || u.severity || u.assignee !== undefined) && !can(p, "cases.triage")) throw new ApiError(403, "The token's owner lacks: cases.triage");
  if (u.status) await setCaseStatus(id, u.status as (typeof CASE_STATUSES)[number], p.id, u.note || undefined);
  if (u.severity) await setCaseSeverity(id, u.severity, p.id);
  if (u.assignee !== undefined) {
    const assignee = u.assignee ? await db.user.findUnique({ where: { email: u.assignee.toLowerCase() }, select: { id: true, active: true, tenantId: true } }) : null;
    if (u.assignee && (!assignee || !assignee.active || assignee.tenantId)) throw new ApiError(400, "No active SOC analyst with that email");
    if (assignee && assignee.id !== p.id && !can(p, "cases.assign")) throw new ApiError(403, "The token's owner lacks: cases.assign");
    await assignCaseTo(id, assignee?.id ?? null, p);
  }
  return getCase(p, id);
}

const commentSchema = z.object({ body: z.string().trim().min(1).max(5000), clientVisible: z.boolean().default(false) }).strict();

export async function commentOnCase(p: ApiPrincipal, id: string, body: unknown) {
  await visibleCase(p, id);
  const c = commentSchema.parse(body);
  const comment = await addComment(id, p, { body: c.body, internal: !c.clientVisible, mentions: [] });
  return { id: comment.id, internal: comment.internal, createdAt: comment.createdAt };
}

export async function lookup(p: ApiPrincipal, params: URLSearchParams) {
  const raw = params.get("value") ?? "";
  const ioc = classifyIndicator(raw);
  if (!ioc) throw new ApiError(400, "value must be an IP, domain, URL, SHA-256/MD5 hash or email address");
  const result = await lookupIndicator(ioc.type, ioc.value, { force: params.get("refresh") === "1" });
  const i = result.indicator;
  return {
    type: i.type,
    value: i.value,
    verdict: indicatorVerdict(i),
    reputation: i.maliciousScore,
    reasons: indicatorReasons(i),
    sources: i.sources,
    blocked: !!i.blockedAt,
    lastCheckedAt: i.lastCheckedAt,
    cached: result.cached,
  };
}

export async function metrics(p: ApiPrincipal, params: URLSearchParams) {
  const range = parseRange({ range: params.get("range") ?? undefined, month: params.get("month") ?? undefined });
  const scope: Prisma.CaseWhereInput = { AND: [caseVisibility(p), ...(params.get("tenantId") && !p.isClient ? [{ tenantId: params.get("tenantId") }] : [])] };
  const r = await loadServiceReport(scope, range);
  return {
    range: { key: range.key, from: range.from, to: range.to },
    openNow: r.openNow,
    opened: r.summary.opened,
    closed: r.summary.closed,
    falsePositives: r.summary.falsePositives,
    medianAcknowledgeMs: r.summary.medianAcknowledgeMs,
    medianContainMs: r.summary.medianContainMs,
    medianResolveMs: r.summary.medianResolveMs,
    sla: r.summary.sla,
    bySeverity: r.summary.bySeverity,
    bySource: r.summary.bySource,
    topTechniques: r.techniques,
    ai: r.ai,
    responseActions: r.actions,
  };
}
