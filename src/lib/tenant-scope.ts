import type { UserRole } from "@prisma/client";

// Split out from tenant.ts so this pure logic can be unit-tested without
// pulling in next-auth (tenant.ts's requireSession() imports @/lib/auth,
// which next-auth can't resolve outside the Next.js runtime — Vitest
// errors on `next/server` the moment anything imports that module graph).

export interface TenantContext {
  userId: string;
  role: UserRole;
  organizationId: string | null;
}

const PLATFORM_ROLES: UserRole[] = ["PLATFORM_OWNER", "PLATFORM_ANALYST"];

export function isPlatformRole(role: UserRole): boolean {
  return PLATFORM_ROLES.includes(role);
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
