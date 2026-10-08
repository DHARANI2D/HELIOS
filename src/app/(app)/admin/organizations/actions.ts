"use server";

import { revalidatePath } from "next/cache";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import {
  createOrganization,
  listOrganizations,
  getOrganizationDetail,
  updateOrganization,
  createSubscription,
  createInvoice,
  type CreateOrganizationInput,
  type InvoiceLineInput,
} from "@/lib/billing/service";
import type { AiTier, OrganizationStatus } from "@prisma/client";

export async function listOrganizationsAction() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  return listOrganizations();
}

export async function getOrganizationDetailAction(id: string) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  return getOrganizationDetail(id);
}

export async function createOrganizationAction(input: CreateOrganizationInput) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  const result = await createOrganization(input, ctx.userId);
  revalidatePath("/admin/organizations");
  return { organizationId: result.organization.id, tempPassword: result.tempPassword };
}

export async function updateOrganizationAction(
  id: string,
  data: { aiTier?: AiTier; status?: OrganizationStatus; selfHostedOllamaUrl?: string | null },
) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  await updateOrganization(id, data, ctx.userId);
  revalidatePath(`/admin/organizations/${id}`);
}

export async function createSubscriptionAction(organizationId: string, planId: string) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  await createSubscription(organizationId, planId, ctx.userId);
  revalidatePath(`/admin/organizations/${organizationId}`);
}

export async function createInvoiceForOrgAction(organizationId: string, lines: InvoiceLineInput[]) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  await createInvoice(organizationId, lines, 14, ctx.userId);
  revalidatePath(`/admin/organizations/${organizationId}`);
  revalidatePath("/admin/billing");
}
