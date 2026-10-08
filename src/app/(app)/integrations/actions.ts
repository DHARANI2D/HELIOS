"use server";

import { revalidatePath } from "next/cache";

import { requireSession, requireOrgContext, tenantWhere } from "@/lib/tenant";
import { createIntegration, listIntegrations, deleteIntegration } from "@/lib/integrations/service";
import type { IntegrationCategory } from "@prisma/client";

export async function listIntegrationsAction() {
  const ctx = await requireSession();
  return listIntegrations(tenantWhere(ctx));
}

export async function createIntegrationAction(vendorLabel: string, category: IntegrationCategory) {
  const ctx = await requireSession();
  const organizationId = requireOrgContext(ctx);
  const integration = await createIntegration(organizationId, vendorLabel, category, ctx.userId);
  revalidatePath("/integrations");
  return integration;
}

export async function deleteIntegrationAction(id: string) {
  const ctx = await requireSession();
  await deleteIntegration(id, tenantWhere(ctx), ctx.userId);
  revalidatePath("/integrations");
}
