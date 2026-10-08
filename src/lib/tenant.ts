import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { isPlatformRole, type TenantContext } from "@/lib/tenant-scope";

export { isPlatformRole, tenantWhere, type TenantContext } from "@/lib/tenant-scope";

// The one place every Server Component/Server Action reads "who is asking
// and what tenant are they in". Mirrors the redirect-to-/login pattern
// (app)/layout.tsx already used pre-tenancy.
export async function requireSession(): Promise<TenantContext> {
  const session = await auth();
  if (!session?.user) redirect("/login");

  return {
    userId: session.user.id,
    role: session.user.role as TenantContext["role"],
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
