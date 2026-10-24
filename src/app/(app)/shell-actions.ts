"use server";

import { cookies } from "next/headers";

import { db } from "@/lib/db";
import { requireUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { TENANT_COOKIE, caseScope, tenantScope } from "@/lib/access";
import { listNotifications, markNotificationsRead } from "@/lib/notifications";

// Staff-only "focus on one client" switch. A preference, not a permission:
// queries still apply the viewer's own visibility rules on top of it.
export async function setTenantFilterAction(tenantId: string) {
  const user = await requireUser();
  if (user.isClient) return;
  const store = await cookies();
  if (tenantId === "all") {
    store.delete(TENANT_COOKIE);
    return;
  }
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { id: true } });
  if (!tenant) throw new Error("Unknown client");
  store.set(TENANT_COOKIE, tenant.id, { path: "/", sameSite: "lax", httpOnly: true, maxAge: 60 * 60 * 24 * 30 });
}

export async function getNotificationsAction() {
  const user = await requireUser();
  const { items, unread } = await listNotifications(user.id, 25);
  return {
    unread,
    items: items.map((n) => ({ id: n.id, kind: n.kind, title: n.title, body: n.body, href: n.href, actorName: n.actorName, read: !!n.readAt, createdAt: n.createdAt.toISOString() })),
  };
}

export async function markNotificationsReadAction(ids?: string[]) {
  const user = await requireUser();
  await markNotificationsRead(user.id, ids?.slice(0, 100));
}

export interface SearchHit {
  kind: "case" | "endpoint" | "indicator" | "tenant";
  id: string;
  title: string;
  subtitle: string;
  href: string;
}

// Command palette search: cases within the viewer's scope, plus endpoints,
// indicators and clients where their role can see them.
export async function globalSearchAction(query: string): Promise<SearchHit[]> {
  const user = await requireUser();
  const q = query.trim().slice(0, 100);
  if (q.length < 2) return [];
  const contains = { contains: q, mode: "insensitive" as const };
  const tenantFilter = await tenantScope(user);

  const [cases, endpoints, indicators, tenants] = await Promise.all([
    can(user, "cases.view")
      ? db.case.findMany({
          where: { AND: [await caseScope(user), { OR: [{ title: contains }, { id: q }, { sourceRef: contains }] }] },
          select: { id: true, title: true, severity: true, status: true, tenant: { select: { name: true } } },
          orderBy: { updatedAt: "desc" },
          take: 6,
        })
      : [],
    can(user, "endpoints.view")
      ? db.endpoint.findMany({ where: { ...tenantFilter, OR: [{ hostname: contains }, { ipAddress: contains }, { owner: contains }] }, select: { id: true, hostname: true, os: true, isolated: true }, take: 4 })
      : [],
    can(user, "intel.view") ? db.threatIndicator.findMany({ where: { value: contains }, select: { id: true, type: true, value: true, maliciousScore: true }, take: 4 }) : [],
    can(user, "tenants.view") ? db.tenant.findMany({ where: { name: contains }, select: { id: true, name: true, plan: true }, take: 3 }) : [],
  ]);

  return [
    ...cases.map((c) => ({ kind: "case" as const, id: c.id, title: c.title, subtitle: `${c.severity.toLowerCase()} · ${c.status.toLowerCase().replaceAll("_", " ")}${c.tenant ? ` · ${c.tenant.name}` : ""}`, href: `/cases/${c.id}` })),
    ...endpoints.map((e) => ({ kind: "endpoint" as const, id: e.id, title: e.hostname, subtitle: `${e.os ?? "unknown OS"}${e.isolated ? " · isolated" : ""}`, href: `/endpoints?q=${encodeURIComponent(e.hostname)}` })),
    ...indicators.map((i) => ({ kind: "indicator" as const, id: i.id, title: i.value, subtitle: `${i.type.toLowerCase().replace("_", " ")}${i.maliciousScore !== null ? ` · score ${i.maliciousScore.toFixed(2)}` : ""}`, href: `/threat-intel?q=${encodeURIComponent(i.value)}` })),
    ...tenants.map((t) => ({ kind: "tenant" as const, id: t.id, title: t.name, subtitle: `${t.plan} plan`, href: `/tenants/${t.id}` })),
  ];
}
