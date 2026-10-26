import { cache } from "react";
import { forbidden, redirect } from "next/navigation";
import type { SecurityDomain, UserRole } from "@prisma/client";

import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { can, isClientRole, type Permission } from "@/lib/rbac";
import { getSetting } from "@/lib/settings";

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
  // Two-step sign-in is required for this account and not set up yet: the
  // app is closed to it until it is (Account → Security).
  mfaPending?: boolean;
  mfaEnabled?: boolean;
}

export const currentUser = cache(async (): Promise<SessionUser | null> => {
  const session = await auth();
  const id = session?.user?.id;
  if (!id) return null;
  const [user, mfaPolicy] = await Promise.all([
    db.user.findUnique({
      where: { id },
      select: { id: true, role: true, name: true, email: true, active: true, tenantId: true, domains: true, mfaEnabledAt: true, tenant: { select: { name: true, status: true } } },
    }),
    getSetting("security.mfa"),
  ]);
  if (!user || !user.active) return null;
  if (user.tenant?.status === "SUSPENDED") return null;
  const mfaRequired = mfaPolicy === "everyone" || (mfaPolicy === "staff" && !isClientRole(user.role));
  return {
    mfaEnabled: !!user.mfaEnabledAt,
    mfaPending: mfaRequired && !user.mfaEnabledAt && session?.user?.via !== "sso",
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
  if (user.mfaPending) throw new Error("Set up two-step sign-in first (Account → Security)");
  return user;
}

// For the two-step sign-in setup itself, which a pending account must reach.
export async function requireUserForMfaSetup(): Promise<SessionUser> {
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
  if (user.mfaPending) redirect("/account/security");
  if (permissions.some((p) => !can(user, p))) forbidden();
  return user;
}
