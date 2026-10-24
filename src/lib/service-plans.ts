import { db } from "@/lib/db";
import { parsePlan, type ServicePlan } from "@/lib/plans";

// Service plans from the database.

export async function listPlans(opts: { includeInactive?: boolean } = {}): Promise<ServicePlan[]> {
  const rows = await db.servicePlan.findMany({
    where: opts.includeInactive ? {} : { active: true },
    orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
  });
  return rows.map(parsePlan);
}

export async function planForTenant(tenantId: string | null | undefined): Promise<ServicePlan | null> {
  if (!tenantId) return null;
  const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { plan: true } });
  return tenant?.plan ? parsePlan(tenant.plan) : null;
}
