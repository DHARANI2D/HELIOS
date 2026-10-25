import type { SecurityDomain, UserRole } from "@prisma/client";

import { db } from "@/lib/db";

// In-app notifications. Every collaboration event (mention, assignment,
// escalation, share, AI triage finished, approval needed, SLA breach, a
// quote request from the website) fans
// out through notify(); the bell in the top bar polls for them.

export type NotificationKind = "mention" | "assigned" | "escalated" | "shared" | "watching" | "approval" | "ai" | "sla" | "lead";

export interface NotifyInput {
  kind: NotificationKind;
  title: string;
  body?: string | null;
  href?: string | null;
  caseId?: string | null;
  actorName?: string | null;
}

export async function notify(userIds: Iterable<string>, input: NotifyInput, options: { exclude?: string | null } = {}) {
  const ids = [...new Set(userIds)].filter((id) => id && id !== options.exclude);
  if (ids.length === 0) return 0;
  const active = await db.user.findMany({ where: { id: { in: ids }, active: true }, select: { id: true } });
  if (active.length === 0) return 0;
  const { count } = await db.notification.createMany({
    data: active.map(({ id }) => ({
      userId: id,
      kind: input.kind,
      title: input.title.slice(0, 200),
      body: input.body?.slice(0, 2000) ?? null,
      href: input.href ?? (input.caseId ? `/cases/${input.caseId}` : null),
      caseId: input.caseId ?? null,
      actorName: input.actorName ?? null,
    })),
  });
  return count;
}

// Everyone following a case: its watchers and its assignee.
export async function caseAudience(caseId: string): Promise<string[]> {
  const [watchers, kase] = await Promise.all([
    db.caseWatcher.findMany({ where: { caseId }, select: { userId: true } }),
    db.case.findUnique({ where: { id: caseId }, select: { assignedToId: true } }),
  ]);
  return [...new Set([...watchers.map((w) => w.userId), ...(kase?.assignedToId ? [kase.assignedToId] : [])])];
}

// Staff who can act on a case: the given roles, narrowed to analysts whose
// queues cover the case's domain (or who have no queue restriction).
export async function staffFor(roles: UserRole[], domain?: SecurityDomain | null) {
  const users = await db.user.findMany({
    where: { active: true, tenantId: null, role: { in: roles } },
    select: { id: true, domains: true },
  });
  return users.filter((u) => !domain || u.domains.length === 0 || u.domains.includes(domain)).map((u) => u.id);
}

export async function listNotifications(userId: string, limit = 20) {
  const [items, unread] = await Promise.all([
    db.notification.findMany({ where: { userId }, orderBy: { createdAt: "desc" }, take: limit }),
    db.notification.count({ where: { userId, readAt: null } }),
  ]);
  return { items, unread };
}

export async function markNotificationsRead(userId: string, ids?: string[]) {
  await db.notification.updateMany({
    where: { userId, readAt: null, ...(ids ? { id: { in: ids } } : {}) },
    data: { readAt: new Date() },
  });
}
