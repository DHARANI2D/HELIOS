import { redirect } from "next/navigation";
import type { UserRole } from "@prisma/client";

import { auth } from "@/lib/auth";

export interface TenantContext {
  userId: string;
  role: UserRole;
  organizationId: string | null;
}

const PLATFORM_ROLES: UserRole[] = ["PLATFORM_OWNER", "PLATFORM_ANALYST"];

export function isPlatformRole(role: UserRole): boolean {
  return PLATFORM_ROLES.includes(role);
}

// The one place every Server Component/Server Action reads "who is asking
// and what tenant are they in". Mirrors the redirect-to-/login pattern
// (app)/layout.tsx already used pre-tenancy.
export async function requireSession(): Promise<TenantContext> {
  const session = await auth();
  if (!session?.user) redirect("/login");

  return {
    userId: session.user.id,
    role: session.user.role as UserRole,
    organizationId: session.user.organizationId ?? null,
  };
}

// Platform-owner-only pages (/admin/*) call this after requireSession().
export function requirePlatformRole(ctx: TenantContext): void {
  if (!isPlatformRole(ctx.role)) redirect("/");
}

// Org-facing-only pages (e.g. a tenant can't be a platform operator) call
// this and get back a guaranteed non-null organizationId to scope with.
export function requireOrgContext(ctx: TenantContext): string {
  if (isPlatformRole(ctx.role) || !ctx.organizationId) redirect("/");
  return ctx.organizationId;
}

// Spread into any Prisma `where` clause on an org-scoped model (Case,
// Agent, IngestedEvent, Playbook, AuditLog). Platform roles get `{}`
// (unscoped — the "minimal workforce operates every tenant" view); org
// roles are pinned to their own organizationId so one tenant's data can
// never leak into another's query results.
export function tenantWhere(ctx: TenantContext): { organizationId?: string } {
  if (isPlatformRole(ctx.role)) return {};
  return { organizationId: ctx.organizationId ?? "__unscoped_org_user__" };
}
