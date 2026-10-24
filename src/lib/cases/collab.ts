import type { UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, caseAudience, staffFor } from "@/lib/notifications";
import { can, isClientRole } from "@/lib/rbac";
import { dispatchChatMessage } from "@/lib/integrations/chat";

// Analyst collaboration on a case: acknowledging (stops the SLA clock),
// discussion with @mentions, watching, escalating to the next tier, handing
// off, and sharing — with teammates, the client, or the client's chat channel.

interface Actor {
  id: string;
  name?: string | null;
  role: UserRole;
}

const actorName = (a: Actor) => a.name ?? "An analyst";
const TIER_ROLES: Record<number, UserRole[]> = {
  1: ["TRIAGE_ANALYST"],
  2: ["ANALYST"],
  3: ["INCIDENT_RESPONDER", "SOC_MANAGER"],
};
export const TIER_LABEL: Record<number, string> = { 1: "Tier 1 · triage", 2: "Tier 2 · analysis", 3: "Tier 3 · incident response" };

async function caseHeader(caseId: string) {
  return db.case.findUniqueOrThrow({ where: { id: caseId }, select: { id: true, title: true, tenantId: true, domain: true, tier: true, status: true, assignedToId: true, acknowledgedAt: true, severity: true } });
}

async function watch(caseId: string, userId: string) {
  await db.caseWatcher.upsert({ where: { caseId_userId: { caseId, userId } }, update: {}, create: { caseId, userId } });
}

export async function acknowledgeCase(caseId: string, actor: Actor) {
  const kase = await caseHeader(caseId);
  if (kase.acknowledgedAt) return kase;
  const updated = await db.case.update({
    where: { id: caseId },
    data: {
      acknowledgedAt: new Date(),
      ...(kase.assignedToId ? {} : { assignedToId: actor.id }),
      ...(kase.status === "OPEN" ? { status: "TRIAGING" } : {}),
    },
  });
  await watch(caseId, actor.id);
  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: actorName(actor), action: "case.acknowledged", detail: "Acknowledged — SLA clock stopped" } });
  await logAction({ actorId: actor.id, caseId, action: "case.acknowledged" });
  return updated;
}

export async function assignCaseTo(caseId: string, assigneeId: string | null, actor: Actor) {
  if (assigneeId) {
    const assignee = await db.user.findFirst({ where: { id: assigneeId, active: true, tenantId: null }, select: { id: true, role: true } });
    if (!assignee || !can(assignee, "cases.view")) throw new Error("Can only assign to active SOC staff");
  }
  await db.case.update({ where: { id: caseId }, data: { assignedToId: assigneeId } });
  if (assigneeId) await watch(caseId, assigneeId);
  await logAction({ actorId: actor.id, caseId, action: "case.assigned", detail: { assigneeId } });
  if (assigneeId) {
    const kase = await caseHeader(caseId);
    await notify([assigneeId], { kind: "assigned", title: `Assigned to you: ${kase.title}`, caseId, actorName: actorName(actor) }, { exclude: actor.id });
  }
}

export async function setWatching(caseId: string, userId: string, watching: boolean) {
  if (watching) await watch(caseId, userId);
  else await db.caseWatcher.deleteMany({ where: { caseId, userId } });
}

// Mentions are user ids picked in the composer; only people who can see the
// case are notified (and, on client-visible comments, client users of the
// case's tenant).
export async function addComment(caseId: string, actor: Actor, input: { body: string; internal: boolean; mentions: string[] }) {
  const kase = await caseHeader(caseId);
  const internal = isClientRole(actor.role) ? false : input.internal;
  const candidates = input.mentions.length
    ? await db.user.findMany({ where: { id: { in: input.mentions.slice(0, 20) }, active: true }, select: { id: true, tenantId: true, role: true } })
    : [];
  const mentions = candidates
    .filter((u) => (u.tenantId === null ? can(u, "cases.view") : !internal && u.tenantId === kase.tenantId))
    .map((u) => u.id);

  const comment = await db.caseComment.create({
    data: { caseId, authorId: actor.id, authorName: actorName(actor), body: input.body, internal, mentions },
  });
  if (!isClientRole(actor.role)) await watch(caseId, actor.id);
  await logAction({ actorId: actor.id, caseId, action: "case.commented", detail: { commentId: comment.id, internal, mentions: mentions.length } });

  const preview = input.body.length > 160 ? `${input.body.slice(0, 157)}…` : input.body;
  await notify(mentions, { kind: "mention", title: `${actorName(actor)} mentioned you on ${kase.title}`, body: preview, caseId, actorName: actorName(actor) }, { exclude: actor.id });
  const watchers = (await caseAudience(caseId)).filter((id) => !mentions.includes(id));
  await notify(watchers, { kind: "watching", title: `New comment on ${kase.title}`, body: preview, caseId, actorName: actorName(actor) }, { exclude: actor.id });
  // Client-visible replies from the SOC reach the client's users.
  if (!internal && !isClientRole(actor.role) && kase.tenantId) {
    const clientUsers = await db.user.findMany({ where: { tenantId: kase.tenantId, active: true }, select: { id: true } });
    await notify(clientUsers.map((u) => u.id).filter((id) => !mentions.includes(id)), { kind: "shared", title: `Update from your SOC: ${kase.title}`, body: preview, caseId, actorName: actorName(actor) });
  }
  // A client comment pages whoever is working the case.
  if (isClientRole(actor.role)) {
    const audience = kase.assignedToId ? [kase.assignedToId] : await staffFor(TIER_ROLES[kase.tier] ?? ["ANALYST"], kase.domain);
    await notify(audience, { kind: "shared", title: `Client replied on ${kase.title}`, body: preview, caseId, actorName: actorName(actor) });
  }
  return comment;
}

export async function escalateCase(caseId: string, actor: Actor, input: { tier: number; assigneeId?: string | null; note?: string }) {
  const kase = await caseHeader(caseId);
  const tier = Math.min(3, Math.max(1, Math.round(input.tier)));
  if (input.assigneeId !== undefined) await assignCaseTo(caseId, input.assigneeId, actor);
  await db.case.update({ where: { id: caseId }, data: { tier, ...(kase.status === "OPEN" || kase.status === "TRIAGING" ? { status: "INVESTIGATING" } : {}) } });
  const direction = tier > kase.tier ? "Escalated" : tier < kase.tier ? "De-escalated" : "Handed off";
  const body = `${direction} to ${TIER_LABEL[tier]}${input.note ? `\n\n${input.note}` : ""}`;
  await db.caseComment.create({ data: { caseId, authorId: actor.id, authorName: actorName(actor), kind: "escalation", body, internal: true } });
  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: actorName(actor), action: "case.escalated", detail: `${direction}: tier ${kase.tier} → ${tier}` } });
  await logAction({ actorId: actor.id, caseId, action: "case.escalated", detail: { from: kase.tier, to: tier, assigneeId: input.assigneeId, note: input.note } });
  if (!input.assigneeId) {
    await notify(await staffFor(TIER_ROLES[tier], kase.domain), { kind: "escalated", title: `${direction} to tier ${tier}: ${kase.title}`, body: input.note ?? null, caseId, actorName: actorName(actor) }, { exclude: actor.id });
  }
}

export type ShareTarget = "teammates" | "client" | "chat";

export async function shareCase(caseId: string, actor: Actor, input: { target: ShareTarget; userIds?: string[]; note?: string }) {
  const kase = await caseHeader(caseId);
  const note = input.note?.trim();
  let summary: string;

  if (input.target === "teammates") {
    const staff = await db.user.findMany({ where: { id: { in: (input.userIds ?? []).slice(0, 25) }, active: true, tenantId: null }, select: { id: true, role: true } });
    const ids = staff.filter((u) => can(u, "cases.view")).map((u) => u.id);
    if (ids.length === 0) throw new Error("Pick at least one teammate");
    for (const id of ids) await watch(caseId, id);
    await notify(ids, { kind: "shared", title: `${actorName(actor)} shared ${kase.title}`, body: note ?? null, caseId, actorName: actorName(actor) }, { exclude: actor.id });
    summary = `Shared with ${ids.length} teammate${ids.length === 1 ? "" : "s"}`;
  } else if (input.target === "client") {
    if (!kase.tenantId) throw new Error("This case isn't linked to a client");
    await db.caseComment.create({
      data: { caseId, authorId: actor.id, authorName: actorName(actor), kind: "share", internal: false, body: note || "Your SOC has shared this incident with you. We'll post updates here." },
    });
    const clientUsers = await db.user.findMany({ where: { tenantId: kase.tenantId, active: true }, select: { id: true } });
    await notify(clientUsers.map((u) => u.id), { kind: "shared", title: `Incident shared by your SOC: ${kase.title}`, body: note ?? null, caseId, actorName: actorName(actor) });
    summary = `Shared with the client (${clientUsers.length} user${clientUsers.length === 1 ? "" : "s"} notified)`;
  } else {
    const result = await dispatchChatMessage(kase.tenantId, `🛡️ ${kase.severity} · ${kase.title}${note ? `\n${note}` : ""}\n${process.env.AUTH_URL ?? ""}/cases/${caseId}`);
    summary = result.message;
  }

  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: actorName(actor), action: "case.shared", detail: summary } });
  await logAction({ actorId: actor.id, caseId, action: "case.shared", detail: { target: input.target, note, summary } });
  return summary;
}

// An AI report draft becomes a client-visible update once an analyst
// publishes it.
export async function publishReport(caseId: string, commentId: string, actor: Actor) {
  const draft = await db.caseComment.findFirstOrThrow({ where: { id: commentId, caseId, kind: "ai_report" } });
  const published = await db.caseComment.create({
    data: { caseId, authorId: actor.id, authorName: `${actorName(actor)} (reviewed AI draft)`, kind: "report", internal: false, body: draft.body },
  });
  await logAction({ actorId: actor.id, caseId, action: "case.report_published", detail: { draftId: commentId, commentId: published.id } });
  const kase = await caseHeader(caseId);
  if (kase.tenantId) {
    const clientUsers = await db.user.findMany({ where: { tenantId: kase.tenantId, active: true }, select: { id: true } });
    await notify(clientUsers.map((u) => u.id), { kind: "shared", title: `Incident report: ${kase.title}`, caseId, actorName: actorName(actor) });
  }
  return published;
}
