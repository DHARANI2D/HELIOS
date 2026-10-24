import { cache } from "react";
import { forbidden, redirect } from "next/navigation";
import type { SecurityDomain, UserRole } from "@prisma/client";

import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { can, isClientRole, type Permission } from "@/lib/rbac";

// Server Actions are public POST endpoints — the proxy redirect and
// render-time gating are not a security boundary (see the Next.js Server
// Actions guide), so every mutating action calls one of these first.
//
// The role, tenant and queues are re-read from the database on every
// request rather than trusted from the JWT, so a role change or
// deactivation takes effect immediately instead of at token expiry.

export interface SessionUser {
  id: string;
  role: UserRole;
  name?: string | null;
  email?: string | null;
  tenantId: string | null;
  tenantName: string | null;
  domains: SecurityDomain[];
  isClient: boolean;
}

export const currentUser = cache(async (): Promise<SessionUser | null> => {
  const session = await auth();
  const id = session?.user?.id;
  if (!id) return null;
  const user = await db.user.findUnique({
    where: { id },
    select: { id: true, role: true, name: true, email: true, active: true, tenantId: true, domains: true, tenant: { select: { name: true, status: true } } },
  });
  if (!user || !user.active) return null;
  if (user.tenant?.status === "SUSPENDED") return null;
  return {
    id: user.id,
    role: user.role,
    name: user.name,
    email: user.email,
    tenantId: user.tenantId,
    tenantName: user.tenant?.name ?? null,
    domains: user.domains,
    isClient: isClientRole(user.role),
  };
});

export async function requireUser(): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) throw new Error("Unauthorized");
  return user;
}

export async function requirePermission(...permissions: Permission[]): Promise<SessionUser> {
  const user = await requireUser();
  const missing = permissions.filter((p) => !can(user, p));
  if (missing.length) throw new Error(`Forbidden: requires ${missing.join(", ")}`);
  return user;
}

// Destructive or org-wide operations (global purge, user management).
export async function requireAdmin(): Promise<SessionUser> {
  const user = await requireUser();
  if (user.role !== "ADMIN") throw new Error("Forbidden: admin role required");
  return user;
}

// For pages: redirects signed-out visitors, renders the 403 page for
// signed-in users without the permission.
export async function pageGuard(...permissions: Permission[]): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) redirect("/login");
  if (permissions.some((p) => !can(user, p))) forbidden();
  return user;
}
