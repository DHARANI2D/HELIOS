import { db } from "@/lib/db";
import type { SessionUser } from "@/lib/session";

// Which client a new case belongs to. Staff pick one (default: the tenant
// switcher's focus); client users can only ever file into their own.

export interface TenantOption {
  id: string;
  name: string;
}

export async function tenantOptions(): Promise<TenantOption[]> {
  return db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true, name: true }, orderBy: { name: "asc" } });
}

export async function resolveTenantInput(user: SessionUser, raw: unknown): Promise<string | null> {
  if (user.isClient) return user.tenantId;
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value || value === "none") return null;
  const tenant = await db.tenant.findUnique({ where: { id: value }, select: { id: true, status: true } });
  if (!tenant || tenant.status === "SUSPENDED") throw new Error("Unknown or suspended client");
  return tenant.id;
}
