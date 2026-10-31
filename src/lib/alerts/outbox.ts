import { Prisma, type AlertDelivery } from "@prisma/client";

import { db } from "@/lib/db";
import { getSetting } from "@/lib/settings";
import { channelStatus, sendAlert } from "@/lib/alerts/send";
import { E164, channelsFor, parsePrefs, type AlertChannel } from "@/lib/alerts/kinds";

// The outbox for alerts outside HELIOS. notify() queues one delivery per
// person and channel they chose for that kind of notification; approver
// chains queue to a contact directly. The worker (lib/jobs, every 10 s)
// claims each due delivery with a lease, sends it, and retries with backoff;
// a permanent failure or the fifth attempt marks it failed. Rows that can't
// be sent at all (channel not set up, no phone number, over the hourly cap)
// are kept as SKIPPED, so the gap is visible.

const MAX_ATTEMPTS = 5;
const BACKOFF_MIN = [1, 5, 15, 60];
const LEASE_MS = 2 * 60_000;

export interface AlertInput {
  kind: string;
  subject: string;
  body?: string | null;
  href?: string | null;
  caseId?: string | null;
  tenantId?: string | null;
}

const absolute = (href: string | null | undefined) => (href ? (/^https?:\/\//.test(href) ? href : `${(process.env.AUTH_URL ?? "").replace(/\/+$/, "")}${href}`) : null);

async function overCap(where: { userId?: string; to?: string }, now: Date) {
  const { maxPerUserPerHour } = await getSetting("alerts.messaging");
  const sent = await db.alertDelivery.count({ where: { ...where, status: { not: "SKIPPED" }, createdAt: { gte: new Date(now.getTime() - 3_600_000) } } });
  return sent >= maxPerUserPerHour ? maxPerUserPerHour : null;
}

// One delivery row, or a SKIPPED one saying why it can't go.
async function enqueue(row: { userId?: string | null; channel: AlertChannel; to: string | null; input: AlertInput; urgent?: boolean }, ready: Awaited<ReturnType<typeof channelStatus>>, now: Date) {
  const { userId = null, channel, to, input, urgent = false } = row;
  const base = { userId, tenantId: input.tenantId ?? null, channel, to: to ?? "", kind: input.kind, subject: input.subject.slice(0, 200), body: (input.body ?? "").slice(0, 2000), href: absolute(input.href ?? (input.caseId ? `/cases/${input.caseId}` : null)), caseId: input.caseId ?? null };
  let skip: string | null = null;
  if (!ready[channel].ready) skip = ready[channel].reason ?? "Channel not set up";
  else if (!to) skip = channel === "email" ? "No email address" : "No phone number on the account";
  else if (channel !== "email" && !E164.test(to)) skip = "The phone number isn't in international format";
  else if (!urgent) {
    const cap = await overCap(userId ? { userId } : { to }, now);
    if (cap) skip = `Over ${cap} alerts in the hour: the rest wait in the app`;
  }
  return db.alertDelivery.create({ data: { ...base, ...(skip ? { status: "SKIPPED", lastError: skip } : { nextAttemptAt: now }) } });
}

// From notify(): each person's chosen channels for this kind.
export async function queueForUsers(userIds: string[], input: AlertInput, now = new Date()) {
  if (!userIds.length) return 0;
  const users = await db.user.findMany({ where: { id: { in: userIds }, active: true, alertPrefs: { not: Prisma.DbNull } }, select: { id: true, email: true, phone: true, alertPrefs: true, tenantId: true } });
  const wanted = users.flatMap((u) => channelsFor(parsePrefs(u.alertPrefs), input.kind).map((channel) => ({ u, channel })));
  if (!wanted.length) return 0;
  const ready = await channelStatus();
  for (const { u, channel } of wanted) {
    await enqueue({ userId: u.id, channel, to: channel === "email" ? u.email : u.phone, input: { ...input, tenantId: input.tenantId ?? u.tenantId } }, ready, now);
  }
  return wanted.length;
}

// A page to the on-call analyst: by SMS and email whatever the person's
// alert choices, and past the hourly cap.
export async function queueUrgent(userIds: string[], input: AlertInput, now = new Date()) {
  const users = await db.user.findMany({ where: { id: { in: userIds }, active: true }, select: { id: true, email: true, phone: true } });
  const ready = await channelStatus();
  const rows = [];
  for (const u of users) {
    rows.push(await enqueue({ userId: u.id, channel: "sms", to: u.phone, input, urgent: true }, ready, now));
    rows.push(await enqueue({ userId: u.id, channel: "email", to: u.email, input, urgent: true }, ready, now));
  }
  return rows;
}

// An approver in a client's chain, reached at the contact the rulebook gives.
export async function queueToContact(channel: AlertChannel, to: string, input: AlertInput, now = new Date()): Promise<AlertDelivery> {
  return enqueue({ channel, to: to.trim(), input }, await channelStatus(), now);
}

// The worker: claim, send, record.
export async function processDeliveries(now = new Date(), limit = 50) {
  const due = await db.alertDelivery.findMany({ where: { status: "PENDING", nextAttemptAt: { lte: now } }, orderBy: { nextAttemptAt: "asc" }, take: limit });
  let sent = 0;
  let failed = 0;
  for (const d of due) {
    // The lease: another worker sees it as not due until it expires.
    const claimed = await db.alertDelivery.updateMany({ where: { id: d.id, status: "PENDING", attempts: d.attempts }, data: { attempts: { increment: 1 }, nextAttemptAt: new Date(now.getTime() + LEASE_MS) } });
    if (!claimed.count) continue;
    const r = await sendAlert(d.channel as AlertChannel, d.to, { id: d.id, subject: d.subject, body: d.body, link: d.href });
    const attempts = d.attempts + 1;
    if (r.ok) {
      await db.alertDelivery.update({ where: { id: d.id }, data: { status: "SENT", sentAt: new Date(), providerRef: r.providerRef ?? null, lastError: null } });
      sent++;
    } else if (r.permanent || attempts >= MAX_ATTEMPTS) {
      await db.alertDelivery.update({ where: { id: d.id }, data: { status: "FAILED", lastError: r.error ?? "Failed" } });
      failed++;
    } else {
      await db.alertDelivery.update({ where: { id: d.id }, data: { lastError: r.error ?? "Failed", nextAttemptAt: new Date(now.getTime() + BACKOFF_MIN[Math.min(attempts - 1, BACKOFF_MIN.length - 1)] * 60_000) } });
    }
  }
  return { due: due.length, sent, failed };
}

// Deliveries by outcome over the last day, for Settings.
export async function deliveryCounts(now = new Date()) {
  const rows = await db.alertDelivery.groupBy({ by: ["status"], where: { createdAt: { gte: new Date(now.getTime() - 86_400_000) } }, _count: true });
  const n = (s: string) => rows.find((r) => r.status === s)?._count ?? 0;
  return { sent: n("SENT"), failed: n("FAILED"), skipped: n("SKIPPED"), pending: n("PENDING") };
}
