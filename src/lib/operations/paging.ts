import { Prisma, type CaseSeverity, type OnCallPage } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { getSetting } from "@/lib/settings";
import { notify, staffFor } from "@/lib/notifications";
import { queueUrgent } from "@/lib/alerts/outbox";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { SEVERITY_ORDER, severityRank } from "@/lib/severity";
import { formatDateTime } from "@/lib/format";
import { isClientRole } from "@/lib/rbac";
import { generateRotation, onCallAt, type Rotation, type RotaRole } from "@/lib/operations/rota";

// Paging whoever is on call. A page goes to the primary, then the backup,
// then the SOC managers, each after the acknowledgement window passes
// unanswered; a level with nobody on it is skipped. Pages go in the app and
// by SMS and email whatever the person's alert choices. Open cases at or
// above the paging severity that nobody has acknowledged page on their own
// (the job, every minute); the circuit breaker and analysts page too.
// Acknowledging a case's page acknowledges the case.

const DAY = 86_400_000;
const LEVEL_LABEL = ["primary", "backup", "SOC managers"] as const;

// ---------------------------------------------------------------- the rota

export async function onCallNow(at = new Date()) {
  const shifts = await db.onCallShift.findMany({
    where: { startsAt: { lte: at }, endsAt: { gt: at }, user: { active: true } },
    include: { user: { select: { id: true, name: true, email: true, phone: true } } },
  });
  return { primary: onCallAt(shifts, at, "primary"), backup: onCallAt(shifts, at, "backup") };
}

async function staffIds(userIds: string[]) {
  const users = await db.user.findMany({ where: { id: { in: userIds }, active: true, tenantId: null }, select: { role: true } });
  if (users.length !== new Set(userIds).size || users.some((u) => isClientRole(u.role))) throw new Error("Only active SOC staff can be on call");
}

// Replaces the regular shifts in the period it covers; overrides stay.
export async function generateShifts(r: Rotation, actorId: string) {
  await staffIds(r.userIds);
  const shifts = generateRotation(r);
  const from = shifts[0].startsAt;
  const to = shifts[shifts.length - 1].endsAt;
  const roles = r.withBackup ? ["primary", "backup"] : ["primary"];
  await db.$transaction([
    db.onCallShift.deleteMany({ where: { role: { in: roles }, override: false, startsAt: { gte: from, lt: to } } }),
    db.onCallShift.updateMany({ where: { role: { in: roles }, override: false, startsAt: { lt: from }, endsAt: { gt: from } }, data: { endsAt: from } }),
    db.onCallShift.createMany({ data: shifts.map((s) => ({ ...s, createdById: actorId })) }),
  ]);
  await logAction({ actorId, action: "oncall.rota_generated", detail: { from, to, shifts: shifts.length, people: r.userIds, shiftHours: r.shiftHours, withBackup: r.withBackup } });
  return shifts.length;
}

export async function addOverride(input: { userId: string; role: RotaRole; startsAt: Date; endsAt: Date; note: string }, actorId: string) {
  await staffIds([input.userId]);
  if (!(input.endsAt > input.startsAt)) throw new Error("The cover has to end after it starts");
  if (input.endsAt.getTime() - input.startsAt.getTime() > 31 * DAY) throw new Error("Cover is for at most a month; generate a rotation for longer");
  const shift = await db.onCallShift.create({ data: { ...input, note: input.note.trim() || null, override: true, createdById: actorId } });
  await logAction({ actorId, action: "oncall.override_added", detail: { shiftId: shift.id, userId: input.userId, role: input.role, startsAt: input.startsAt, endsAt: input.endsAt, note: input.note } });
  return shift;
}

export async function deleteShift(id: string, actorId: string) {
  const shift = await db.onCallShift.delete({ where: { id } });
  await logAction({ actorId, action: "oncall.shift_deleted", detail: { shiftId: id, userId: shift.userId, role: shift.role, startsAt: shift.startsAt, endsAt: shift.endsAt } });
}

// ---------------------------------------------------------------- pages

async function managers() {
  const ids = await staffFor(["SOC_MANAGER"], null);
  return ids.length ? ids : staffFor(["ADMIN"], null);
}

// Who a page goes to from a level up; an empty level is skipped.
async function targetsFrom(level: number, at: Date): Promise<{ level: number; ids: string[] }> {
  const { primary, backup } = await onCallNow(at);
  for (let l = level; l <= 2; l++) {
    const ids = l === 0 ? (primary ? [primary.userId] : []) : l === 1 ? (backup ? [backup.userId] : []) : await managers();
    if (ids.length) return { level: l, ids };
  }
  return { level: 2, ids: [] };
}

async function send(page: Pick<OnCallPage, "id" | "title" | "body" | "caseId" | "tenantId">, ids: string[], level: number, now: Date) {
  if (!ids.length) return;
  const title = `${level === 1 ? "[No answer from primary] " : level === 2 ? "[Unanswered page] " : ""}${page.title}`;
  const href = `/operations?page=${page.id}`;
  await notify(ids, { kind: "oncall", title, body: page.body, href, caseId: page.caseId });
  await queueUrgent(ids, { kind: "oncall", subject: title, body: page.body, href, caseId: page.caseId, tenantId: page.tenantId }, now);
}

async function names(ids: string[]) {
  const users = await db.user.findMany({ where: { id: { in: ids } }, select: { name: true } });
  return users.map((u) => u.name).join(", ") || "nobody";
}

export interface PageInput {
  // One page per cause: a second page with the same key is not sent.
  key: string;
  title: string;
  body?: string | null;
  caseId?: string | null;
  tenantId?: string | null;
  severity?: CaseSeverity | null;
  createdById?: string | null;
}

export async function pageOnCall(input: PageInput, now = new Date()) {
  const existing = await db.onCallPage.findUnique({ where: { key: input.key } });
  if (existing) return { page: existing, created: false };
  const t = await targetsFrom(0, now);
  let page: OnCallPage;
  try {
    page = await db.onCallPage.create({
      data: { key: input.key, title: input.title.slice(0, 200), body: input.body?.slice(0, 2000) ?? null, caseId: input.caseId ?? null, tenantId: input.tenantId ?? null, severity: input.severity ?? null, createdById: input.createdById ?? null, level: t.level, pagedIds: t.ids, lastPagedAt: now },
    });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") return { page: (await db.onCallPage.findUniqueOrThrow({ where: { key: input.key } })), created: false };
    throw e;
  }
  await send(page, t.ids, t.level, now);
  const who = await names(t.ids);
  if (page.caseId) await db.timelineEntry.create({ data: { caseId: page.caseId, occurredAt: now, actor: "on-call", action: "oncall.paged", detail: `Paged ${LEVEL_LABEL[t.level]}: ${who}` } });
  await logAction({ actorId: input.createdById ?? undefined, caseId: page.caseId ?? undefined, action: "oncall.paged", detail: { pageId: page.id, key: page.key, level: t.level, to: t.ids } });
  return { page, created: true };
}

export async function acknowledgePage(id: string, user: { id: string; name: string }, now = new Date()) {
  const { count } = await db.onCallPage.updateMany({ where: { id, ackAt: null }, data: { ackAt: now, ackById: user.id, ackByName: user.name } });
  if (!count) throw new Error("This page was already answered");
  const page = await db.onCallPage.findUniqueOrThrow({ where: { id } });
  if (page.caseId) {
    const kase = await db.case.findUnique({ where: { id: page.caseId }, select: { acknowledgedAt: true, assignedToId: true } });
    if (kase) {
      await db.case.update({ where: { id: page.caseId }, data: { ...(kase.acknowledgedAt ? {} : { acknowledgedAt: now }), ...(kase.assignedToId ? {} : { assignedToId: user.id }) } });
      await db.timelineEntry.create({ data: { caseId: page.caseId, occurredAt: now, actor: user.name, action: "oncall.acknowledged", detail: `${user.name} answered the page${kase.assignedToId ? "" : " and took the case"}` } });
    }
  }
  await logAction({ actorId: user.id, caseId: page.caseId ?? undefined, action: "oncall.acknowledged", detail: { pageId: id } });
  return page;
}

// Severe cases nobody has acknowledged in time page on their own.
async function openCasePages(now: Date, minSeverity: CaseSeverity) {
  const severities = SEVERITY_ORDER.filter((s) => severityRank(s) >= severityRank(minSeverity));
  const cases = await db.case.findMany({
    where: { severity: { in: severities }, acknowledgedAt: null, status: { notIn: CLOSED_STATUSES }, createdAt: { gte: new Date(now.getTime() - DAY) } },
    select: { id: true, title: true, severity: true, tenantId: true, tenant: { select: { name: true, isTest: true } } },
    orderBy: { createdAt: "asc" },
    take: 50,
  });
  if (!cases.length) return 0;
  const paged = new Set((await db.onCallPage.findMany({ where: { key: { in: cases.map((c) => `case:${c.id}`) } }, select: { key: true } })).map((p) => p.key));
  let opened = 0;
  for (const c of cases) {
    if (paged.has(`case:${c.id}`)) continue;
    const client = c.tenant ? `${c.tenant.name}${c.tenant.isTest ? " (test client)" : ""}` : "Internal";
    const r = await pageOnCall({ key: `case:${c.id}`, title: `${c.severity.toLowerCase()} case: ${c.title}`, body: `${client}. Nobody has acknowledged it yet.`, caseId: c.id, tenantId: c.tenantId, severity: c.severity }, now);
    if (r.created) opened++;
  }
  return opened;
}

// A case acknowledged or closed some other way answers its page.
async function answeredOnCase(now: Date) {
  const open = await db.onCallPage.findMany({ where: { ackAt: null, caseId: { not: null } }, select: { id: true, caseId: true }, take: 500 });
  if (!open.length) return 0;
  const done = await db.case.findMany({ where: { id: { in: open.map((p) => p.caseId!) }, OR: [{ acknowledgedAt: { not: null } }, { status: { in: CLOSED_STATUSES } }] }, select: { id: true } });
  const ids = new Set(done.map((c) => c.id));
  const { count } = await db.onCallPage.updateMany({ where: { id: { in: open.filter((p) => ids.has(p.caseId!)).map((p) => p.id) }, ackAt: null }, data: { ackAt: now, ackByName: "Acknowledged on the case" } });
  return count;
}

async function escalate(now: Date, ackMinutes: number) {
  const due = await db.onCallPage.findMany({ where: { ackAt: null, level: { lt: 2 }, lastPagedAt: { lte: new Date(now.getTime() - ackMinutes * 60_000) } }, take: 50 });
  let moved = 0;
  for (const p of due) {
    const t = await targetsFrom(p.level + 1, now);
    // Claimed, so two instances don't both send it.
    const { count } = await db.onCallPage.updateMany({ where: { id: p.id, level: p.level, ackAt: null }, data: { level: t.level, pagedIds: [...new Set([...p.pagedIds, ...t.ids])], lastPagedAt: now } });
    if (!count) continue;
    await send(p, t.ids, t.level, now);
    if (p.caseId) await db.timelineEntry.create({ data: { caseId: p.caseId, occurredAt: now, actor: "on-call", action: "oncall.escalated", detail: `No answer in ${ackMinutes} minutes; paged ${LEVEL_LABEL[t.level]}: ${await names(t.ids)}` } });
    moved++;
  }
  return moved;
}

// What the next person on call walks into.
export async function handoffSummary(now = new Date()) {
  const [cases, pages, approvals, notices, quiet] = await Promise.all([
    db.case.count({ where: { severity: { in: ["HIGH", "CRITICAL"] }, status: { notIn: CLOSED_STATUSES } } }),
    db.onCallPage.count({ where: { ackAt: null } }),
    db.responseAction.count({ where: { status: "PENDING_APPROVAL" } }),
    db.regulatoryNotice.count({ where: { status: { notIn: ["SUBMITTED", "NOT_REQUIRED"] }, dueAt: { lte: new Date(now.getTime() + 12 * 3_600_000) } } }),
    db.integration.count({ where: { enabled: true, quietSince: { not: null } } }),
  ]);
  return { cases, pages, approvals, notices, quiet };
}

export const handoffText = (h: Awaited<ReturnType<typeof handoffSummary>>) =>
  [`Open high and critical cases: ${h.cases}`, `Unanswered pages: ${h.pages}`, `Containment waiting for approval: ${h.approvals}`, `Regulatory notices due within 12 hours: ${h.notices}`, `Quiet log sources: ${h.quiet}`].join("\n");

async function handoffs(now: Date) {
  const starting = await db.onCallShift.findMany({ where: { handoffSentAt: null, startsAt: { lte: now, gte: new Date(now.getTime() - 2 * 3_600_000) }, endsAt: { gt: now } } });
  let sent = 0;
  for (const s of starting) {
    const { count } = await db.onCallShift.updateMany({ where: { id: s.id, handoffSentAt: null }, data: { handoffSentAt: now } });
    if (!count) continue;
    await notify([s.userId], { kind: "oncall", title: `You're on call (${s.role}) until ${formatDateTime(s.endsAt)}`, body: handoffText(await handoffSummary(now)), href: "/operations" });
    sent++;
  }
  return sent;
}

export async function runPaging(now = new Date()) {
  const s = await getSetting("operations");
  const answered = await answeredOnCase(now);
  const opened = await openCasePages(now, s.pageSeverity);
  const escalated = await escalate(now, s.ackMinutes);
  const handedOver = await handoffs(now);
  return { answered, opened, escalated, handedOver };
}
