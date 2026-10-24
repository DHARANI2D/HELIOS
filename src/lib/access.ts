import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { can } from "@/lib/rbac";
import type { SessionUser } from "@/lib/session";

// Row-level scoping. Client users are pinned to their tenant; staff see every
// tenant (optionally narrowed by the tenant switcher), and analysts with
// security domains see their queues plus anything assigned to them.

export const TENANT_COOKIE = "helios-tenant";

// The tenant the staff switcher is focused on, or null for "all clients".
export async function selectedTenantId(user: SessionUser): Promise<string | null> {
  if (user.isClient) return user.tenantId;
  const value = (await cookies()).get(TENANT_COOKIE)?.value;
  return value && value !== "all" ? value : null;
}

// For tenant-owned rows (events, endpoints, integrations, agents).
export async function tenantScope(user: SessionUser): Promise<{ tenantId?: string | null }> {
  if (user.isClient) return { tenantId: user.tenantId ?? "__none__" };
  const selected = await selectedTenantId(user);
  return selected ? { tenantId: selected } : {};
}

export function caseVisibility(user: SessionUser): Prisma.CaseWhereInput {
  if (user.isClient) return { tenantId: user.tenantId ?? "__none__" };
  if (can(user, "cases.view_all") || user.domains.length === 0) return {};
  return { OR: [{ domain: { in: user.domains } }, { domain: null }, { assignedToId: user.id }] };
}

// Visibility plus the tenant switcher.
export async function caseScope(user: SessionUser): Promise<Prisma.CaseWhereInput> {
  const visibility = caseVisibility(user);
  const selected = user.isClient ? null : await selectedTenantId(user);
  return selected ? { AND: [visibility, { tenantId: selected }] } : visibility;
}

export async function canAccessCase(user: SessionUser, caseId: string): Promise<boolean> {
  const count = await db.case.count({ where: { AND: [{ id: caseId }, caseVisibility(user)] } });
  return count > 0;
}

// Out-of-scope cases 404 rather than 403, so case ids don't leak across tenants.
export async function assertCaseAccess(user: SessionUser, caseId: string, mode: "page" | "action" = "action") {
  if (await canAccessCase(user, caseId)) return;
  if (mode === "page") notFound();
  throw new Error("Case not found");
}

export async function assertTenantAccess(user: SessionUser, tenantId: string | null | undefined) {
  if (!user.isClient) return;
  if (!tenantId || tenantId !== user.tenantId) throw new Error("Not found");
}
