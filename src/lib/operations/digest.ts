import { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { getSetting } from "@/lib/settings";
import { notify, staffFor } from "@/lib/notifications";
import { ACTION_LABEL } from "@/lib/response/labels";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { NOTICE_LABEL } from "@/lib/compliance/notices";
import { formatDateTime } from "@/lib/format";
import { autonomousWhere } from "@/lib/operations/qa";
import { weekStart } from "@/lib/operations/qa-sample";

// The daily digest. At the top of the autonomy ladder the AI acts without
// telling anyone at the time; this is where it reports. Each client's
// admins get theirs (what HELIOS did on their estate, what's waiting on
// them, deadlines), and the SOC managers get one across every client. It
// goes out once a day at the hour set under SOC Operations, in the app and
// by email for those who chose it, and is skipped when there's nothing to
// say.

const DAY = 86_400_000;

export interface DigestSummary {
  scope: { tenantId: string | null; name: string; isTest: boolean };
  from: string;
  to: string;
  aiActions: Array<{ caseId: string; caseTitle: string; action: string; target: string | null; status: string; level: number | null; at: string; qa: string | null }>;
  aiActionsTotal: number;
  rolledBack: number;
  opened: { total: number; critical: number; high: number };
  closed: { total: number; truePositive: number; benign: number; falsePositive: number };
  pendingApprovals: number;
  notices: Array<{ caseId: string; caseTitle: string; kind: string; dueAt: string | null; overdue: boolean }>;
  quietSources: number;
  qa: { reviewed: number; agree: number; partly: number; disagree: number };
  pages: { total: number; unanswered: number } | null;
}

const levelOf = (parameters: Prisma.JsonValue) => {
  const v = parameters && typeof parameters === "object" && !Array.isArray(parameters) ? (parameters as { ladderLevel?: unknown }).ladderLevel : undefined;
  return v == null ? null : Number(v);
};

export async function buildDigest(scope: { id: string | null; name: string; isTest: boolean }, from: Date, to: Date): Promise<DigestSummary> {
  const t = scope.id ? { tenantId: scope.id } : {};
  const range = { gte: from, lt: to };
  const [actions, actionsTotal, rolledBack, opened, closed, pendingApprovals, notices, quietSources, qa, pages] = await Promise.all([
    db.responseAction.findMany({ where: { ...autonomousWhere(), ...t, createdAt: range }, orderBy: { createdAt: "desc" }, take: 30, include: { case: { select: { title: true } } } }),
    db.responseAction.count({ where: { ...autonomousWhere(), ...t, createdAt: range } }),
    db.responseAction.count({ where: { ...autonomousWhere(), ...t, createdAt: range, status: "ROLLED_BACK" } }),
    db.case.groupBy({ by: ["severity"], where: { ...t, createdAt: range }, _count: true }),
    db.case.groupBy({ by: ["disposition"], where: { ...t, resolvedAt: range, status: { in: CLOSED_STATUSES } }, _count: true }),
    db.responseAction.count({ where: { ...t, status: "PENDING_APPROVAL" } }),
    db.regulatoryNotice.findMany({ where: { ...t, status: { notIn: ["SUBMITTED", "NOT_REQUIRED"] }, dueAt: { lte: new Date(to.getTime() + DAY) } }, orderBy: { dueAt: "asc" }, take: 10, include: { case: { select: { title: true } } } }),
    db.integration.count({ where: { ...t, enabled: true, quietSince: { not: null } } }),
    db.qaReview.groupBy({ by: ["outcome"], where: { ...t, status: "DONE", reviewedAt: { gte: weekStart(to) } }, _count: true }),
    scope.id ? Promise.resolve(null) : Promise.all([db.onCallPage.count({ where: { createdAt: range } }), db.onCallPage.count({ where: { ackAt: null } })]),
  ]);
  const sev = (s: string) => opened.find((o) => o.severity === s)?._count ?? 0;
  const disp = (d: string) => closed.find((c) => c.disposition === d)?._count ?? 0;
  const out = (o: string) => qa.find((q) => q.outcome === o)?._count ?? 0;
  return {
    scope: { tenantId: scope.id, name: scope.name, isTest: scope.isTest },
    from: from.toISOString(),
    to: to.toISOString(),
    aiActions: actions.map((a) => ({ caseId: a.caseId, caseTitle: a.case.title, action: ACTION_LABEL[a.actionType], target: a.target, status: a.status, level: levelOf(a.parameters), at: a.createdAt.toISOString(), qa: a.qaVerdict })),
    aiActionsTotal: actionsTotal,
    rolledBack,
    opened: { total: opened.reduce((n, o) => n + o._count, 0), critical: sev("CRITICAL"), high: sev("HIGH") },
    closed: { total: closed.reduce((n, c) => n + c._count, 0), truePositive: disp("TRUE_POSITIVE"), benign: disp("BENIGN_TRUE_POSITIVE"), falsePositive: disp("FALSE_POSITIVE") },
    pendingApprovals,
    notices: notices.map((n) => ({ caseId: n.caseId, caseTitle: n.case.title, kind: NOTICE_LABEL[n.kind], dueAt: n.dueAt?.toISOString() ?? null, overdue: !!n.dueAt && n.dueAt < to })),
    quietSources,
    qa: { reviewed: qa.reduce((n, q) => n + q._count, 0), agree: out("agree"), partly: out("partly"), disagree: out("disagree") },
    pages: pages ? { total: pages[0], unanswered: pages[1] } : null,
  };
}

export const isQuiet = (d: DigestSummary) => !d.aiActionsTotal && !d.opened.total && !d.closed.total && !d.pendingApprovals && !d.notices.length && !d.quietSources && !d.pages?.unanswered;

export function digestText(d: DigestSummary) {
  const lines: string[] = [];
  lines.push(d.aiActionsTotal ? `HELIOS acted on its own ${d.aiActionsTotal} time${d.aiActionsTotal === 1 ? "" : "s"}${d.rolledBack ? ` (${d.rolledBack} rolled back)` : ""}:` : "HELIOS took no action on its own.");
  for (const a of d.aiActions.slice(0, 8)) lines.push(`- ${a.action}${a.target ? ` ${a.target}` : ""} on "${a.caseTitle}"${a.status === "ROLLED_BACK" ? " (rolled back)" : a.status === "FAILED" ? " (failed)" : ""}`);
  if (d.aiActionsTotal > 8) lines.push(`- and ${d.aiActionsTotal - 8} more`);
  lines.push(`Cases: ${d.opened.total} opened${d.opened.critical || d.opened.high ? ` (${[d.opened.critical ? `${d.opened.critical} critical` : "", d.opened.high ? `${d.opened.high} high` : ""].filter(Boolean).join(", ")})` : ""}, ${d.closed.total} closed${d.closed.total ? ` (${d.closed.truePositive} true positive, ${d.closed.benign} benign, ${d.closed.falsePositive} false positive)` : ""}.`);
  if (d.pendingApprovals) lines.push(`Waiting for approval: ${d.pendingApprovals} containment action${d.pendingApprovals === 1 ? "" : "s"}.`);
  for (const n of d.notices) lines.push(`${n.overdue ? "Overdue" : "Due"}: ${n.kind} on "${n.caseTitle}"${n.dueAt ? ` (${formatDateTime(n.dueAt)})` : ""}.`);
  if (d.quietSources) lines.push(`Log sources gone quiet: ${d.quietSources}.`);
  if (d.qa.reviewed) lines.push(`QA this week: ${d.qa.reviewed} reviewed, ${d.qa.agree} right, ${d.qa.partly} partly, ${d.qa.disagree} wrong.`);
  if (d.pages) lines.push(`Pages: ${d.pages.total} sent, ${d.pages.unanswered} unanswered now.`);
  return lines.join("\n");
}

// The date and hour now in the digest's time zone.
export function localNow(now: Date, timeZone: string) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23" }).formatToParts(now).map((p) => [p.type, p.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, hour: Number(parts.hour) };
}

async function recipients(tenantId: string | null) {
  if (!tenantId) return staffFor(["SOC_MANAGER"], null);
  return (await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } })).map((u) => u.id);
}

// The job: once a day per client and for the SOC, at the set hour.
export async function sendDigests(now = new Date()) {
  const { digestHour, timeZone } = await getSetting("operations");
  const local = localNow(now, timeZone);
  if (local.hour < digestHour) return 0;
  const tenants = await db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true, isTest: true }, orderBy: { name: "asc" } });
  let sent = 0;
  for (const scope of [{ id: null, name: "All clients", isTest: false }, ...tenants]) {
    const key = `${scope.id ?? "soc"}:${local.date}`;
    if (await db.digestRun.count({ where: { key } })) continue;
    const last = await db.digestRun.findFirst({ where: { tenantId: scope.id }, orderBy: { toAt: "desc" }, select: { toAt: true } });
    const from = new Date(Math.max(last?.toAt.getTime() ?? now.getTime() - DAY, now.getTime() - 7 * DAY));
    const summary = await buildDigest(scope, from, now);
    const to = isQuiet(summary) ? [] : await recipients(scope.id);
    let run;
    try {
      run = await db.digestRun.create({ data: { key, tenantId: scope.id, day: new Date(`${local.date}T00:00:00Z`), fromAt: from, toAt: now, recipients: to.length, summary: summary as unknown as Prisma.InputJsonValue } });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") continue;
      throw e;
    }
    if (!to.length) continue;
    await notify(to, {
      kind: "digest",
      title: `Daily digest${scope.id ? ` for ${scope.name}` : ""}: ${summary.aiActionsTotal} action${summary.aiActionsTotal === 1 ? "" : "s"} by HELIOS, ${summary.opened.total} new case${summary.opened.total === 1 ? "" : "s"}`,
      body: digestText(summary),
      href: `/digest/${run.id}`,
    });
    sent++;
  }
  return sent;
}
