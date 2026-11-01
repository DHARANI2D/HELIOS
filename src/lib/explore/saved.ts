import { db } from "@/lib/db";
import { dbFor } from "@/lib/tenant-db";

// The saved searches a person sees: their own, and the shared ones on their
// side (their client's, or the SOC's).
export async function savedSearchesFor(user: { id: string; isClient: boolean; tenantId: string | null }) {
  return dbFor(user).savedSearch.findMany({
    where: user.isClient ? { tenantId: user.tenantId ?? "__none__", OR: [{ ownerId: user.id }, { shared: true, owner: { tenantId: user.tenantId } }] } : { OR: [{ ownerId: user.id }, { shared: true, owner: { tenantId: null } }] },
    include: { owner: { select: { name: true, email: true } }, tenant: { select: { name: true } } },
    orderBy: { name: "asc" },
    take: 200,
  });
}

// The clients a member of staff can pick.
export async function tenantsForExplore() {
  return db.tenant.findMany({ select: { id: true, name: true, isTest: true }, orderBy: { name: "asc" } });
}
