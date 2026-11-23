import type { AiSystem } from "@prisma/client";

import { db } from "@/lib/db";
import { dbFor } from "@/lib/tenant-db";
import type { SessionUser } from "@/lib/session";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { guardedCategories } from "@/lib/aisec/guard";
import { postureOf } from "@/lib/aisec/frameworks";
import type { SystemResult } from "@/lib/aisec/redteam";
import { modeOf, policyOf } from "@/lib/aisec/service";
import type { Verdict } from "@/lib/aisec/policy";

// What the AI Security pages show: the systems in scope, their guard
// decisions, red-team results and where they stand on the OWASP Top 10 for
// LLM applications. Read through the user's own scope (row-level security
// for client users).

export type RedTeamSummary = SystemResult & { testId?: string };
export const redTeamOf = (s: Pick<AiSystem, "redTeam">) => (s.redTeam ?? null) as unknown as RedTeamSummary | null;

export interface DecisionRow {
  id: string;
  at: Date;
  system: string;
  systemId: string | null;
  tenantName: string | null;
  stage: string;
  decision: Verdict;
  enforced: Verdict;
  subject: string | null;
  rules: string[];
  owasp: string[];
  excerpt: string | null;
  receipt: string | null;
  caseId: string | null;
  retained: boolean;
  findings: Array<{ rule: string; verdict: string; message: string }>;
}

type Meta = { systemId?: string; stage?: string; decision?: Verdict; enforced?: Verdict; rules?: string[]; owasp?: string[]; excerpt?: string | null; receipt?: string; sealedContent?: string; findings?: DecisionRow["findings"] };

export function decisionRow(e: { id: string; timestamp: Date; service: string | null; userName: string | null; caseId: string | null; metadata: unknown; tenant?: { name: string } | null }): DecisionRow {
  const m = (e.metadata ?? {}) as Meta;
  return {
    id: e.id,
    at: e.timestamp,
    system: e.service ?? "",
    systemId: m.systemId ?? null,
    tenantName: e.tenant?.name ?? null,
    stage: m.stage ?? "",
    decision: m.decision ?? "allow",
    enforced: m.enforced ?? m.decision ?? "allow",
    subject: e.userName,
    rules: m.rules ?? [],
    owasp: m.owasp ?? [],
    excerpt: m.excerpt ?? null,
    receipt: m.receipt ?? null,
    caseId: e.caseId,
    retained: !!m.sealedContent,
    findings: m.findings ?? [],
  };
}

const DAY = 86_400_000;

// tenantScope() always narrows a client user to their own client; counts
// run on the platform client with that filter (grouped queries can't go
// through the scoped one), everything else through the user's scope.
export async function loadOverview(user: SessionUser, scope: { tenantId?: string | null }) {
  const q = dbFor(user);
  const since = new Date(Date.now() - DAY);
  const tenant = scope.tenantId ? { tenantId: scope.tenantId } : {};
  const systems = await q.aiSystem.findMany({ where: { ...tenant, status: { not: "retired" } }, include: { tenant: { select: { name: true } } }, orderBy: [{ tenantId: "asc" }, { name: "asc" }] });
  const events = { ...tenant, platform: "helios-ai-guard" };
  const [byType, recent, openCases] = await Promise.all([
    db.securityEvent.groupBy({ by: ["tenantId", "service", "eventType"], where: { ...events, timestamp: { gte: since } }, _count: { _all: true } }),
    q.securityEvent.findMany({ where: events, orderBy: { timestamp: "desc" }, take: 25, select: { id: true, timestamp: true, service: true, userName: true, caseId: true, metadata: true, tenant: { select: { name: true } } } }),
    q.case.count({ where: { ...tenant, sourceType: "SIEM_ALERT", sourceRef: { startsWith: "ai-system:" }, status: { notIn: CLOSED_STATUSES } } }),
  ]);
  const counts = (s: { tenantId: string; name: string }) => {
    const rows = byType.filter((r) => r.tenantId === s.tenantId && r.service === s.name);
    const n = (d: string) => rows.find((r) => r.eventType === `ai.guard.${d}`)?._count._all ?? 0;
    return { allow: n("allow"), watch: n("watch"), redact: n("redact"), block: n("block"), total: rows.reduce((a, r) => a + r._count._all, 0) };
  };
  const rows = systems.map((s) => ({ system: s, decisions: counts(s), redTeam: redTeamOf(s), guarded: guardedCategories(policyOf(s), modeOf(s)) }));

  // Posture across the systems in scope.
  const guarded: Record<string, number> = {};
  const tested: Record<string, number> = {};
  const open: Record<string, number> = {};
  for (const r of rows) {
    for (const g of r.guarded) guarded[g] = (guarded[g] ?? 0) + 1;
    for (const [k, v] of Object.entries(r.redTeam?.categories ?? {})) {
      if ((v.open ?? 0) > 0) open[k] = (open[k] ?? 0) + (v.open ?? 0);
      else if (v.attempts > 0) tested[k] = (tested[k] ?? 0) + 1;
    }
  }
  const posture = postureOf({ systems: rows.length, guarded, tested, open });
  const totals = rows.reduce((a, r) => ({ allow: a.allow + r.decisions.allow, watch: a.watch + r.decisions.watch, redact: a.redact + r.decisions.redact, block: a.block + r.decisions.block, total: a.total + r.decisions.total }), { allow: 0, watch: 0, redact: 0, block: 0, total: 0 });
  return { rows, recent: recent.map(decisionRow), openCases, posture, totals };
}

export async function loadSystem(user: SessionUser, id: string) {
  const q = dbFor(user);
  const system = await q.aiSystem.findUnique({ where: { id }, include: { tenant: { select: { name: true } }, versions: { orderBy: { version: "desc" }, take: 30 } } });
  if (!system || (user.isClient && user.tenantId !== system.tenantId)) return null;
  const since = new Date(Date.now() - DAY);
  const where = { tenantId: system.tenantId, platform: "helios-ai-guard", service: system.name };
  const [byType, recent, cases, test] = await Promise.all([
    db.securityEvent.groupBy({ by: ["eventType"], where: { ...where, timestamp: { gte: since } }, _count: { _all: true } }),
    q.securityEvent.findMany({ where, orderBy: { timestamp: "desc" }, take: 50, select: { id: true, timestamp: true, service: true, userName: true, caseId: true, metadata: true } }),
    q.case.findMany({ where: { tenantId: system.tenantId, sourceType: "SIEM_ALERT", sourceRef: `ai-system:${system.id}` }, orderBy: { createdAt: "desc" }, take: 5, select: { id: true, title: true, status: true, severity: true, createdAt: true } }),
    redTeamOf(system)?.testId ? q.securityTest.findUnique({ where: { id: redTeamOf(system)!.testId! }, select: { id: true, title: true, status: true, findings: true, windowEnd: true } }) : Promise.resolve(null),
  ]);
  const n = (d: string) => byType.find((r) => r.eventType === `ai.guard.${d}`)?._count._all ?? 0;
  return { system, decisions: { allow: n("allow"), watch: n("watch"), redact: n("redact"), block: n("block") }, recent: recent.map((e) => decisionRow(e)).filter((r) => !r.systemId || r.systemId === system.id), cases, test };
}
