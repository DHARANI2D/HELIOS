"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission, requireUser, type SessionUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { resolveTenantInput } from "@/lib/tenants";
import { applyInventory, parseInventoryCsv, setEndpointIsolated } from "@/lib/endpoints/service";
import { action } from "@/lib/action";

async function endpointInScope(user: SessionUser, id: string) {
  const endpoint = await db.endpoint.findUniqueOrThrow({ where: { id } });
  if (user.isClient && endpoint.tenantId !== user.tenantId) throw new Error("Not found");
  return endpoint;
}

export const setIsolationAction = action(async function setIsolationAction(endpointId: string, isolate: boolean) {
  const user = await requirePermission("endpoints.contain");
  await endpointInScope(user, endpointId);
  const result = await setEndpointIsolated(endpointId, isolate, { id: user.id, name: user.name ?? "analyst" });
  revalidatePath("/endpoints");
  return { manual: !result.dispatched, message: result.message };
});

// Criticality drives the auto-isolation guardrail, so SOC containment staff
// and the client's own admins can set it.
export const updateEndpointAction = action(async function updateEndpointAction(endpointId: string, input: { criticality: string; owner?: string }) {
  const user = await requireUser();
  if (!can(user, "endpoints.contain") && !can(user, "integrations.manage")) throw new Error("Forbidden");
  await endpointInScope(user, endpointId);
  const criticality = z.enum(["standard", "high", "critical"]).parse(input.criticality);
  await db.endpoint.update({ where: { id: endpointId }, data: { criticality, owner: input.owner?.trim().slice(0, 120) || undefined } });
  await logAction({ actorId: user.id, action: "endpoint.updated", detail: { endpointId, criticality } });
  revalidatePath("/endpoints");
});

export const importInventoryAction = action(async function importInventoryAction(csv: string, tenantId?: string) {
  const user = await requirePermission("integrations.manage");
  const records = parseInventoryCsv(csv.slice(0, 2_000_000));
  if (records.length === 0) throw new Error("No rows with a hostname");
  const tenant = await resolveTenantInput(user, tenantId);
  const count = await applyInventory(tenant, records, "CSV import");
  await logAction({ actorId: user.id, action: "endpoint.inventory_imported", detail: { count, tenantId: tenant } });
  revalidatePath("/endpoints");
  return count;
});
