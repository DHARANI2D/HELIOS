"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission, requireUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { PLAN_KEYS, planFor, type PlanKey } from "@/lib/plans";

const tenantSchema = z.object({
  name: z.string().trim().min(2).max(120),
  industry: z.string().trim().max(80).optional(),
  plan: z.enum(PLAN_KEYS as [PlanKey, ...PlanKey[]]),
  status: z.enum(["ONBOARDING", "ACTIVE", "SUSPENDED"]),
  contactName: z.string().trim().max(120).optional(),
  contactEmail: z.string().trim().email().max(200).optional().or(z.literal("")),
  endpointsLicensed: z.number().int().min(0).max(1_000_000),
  usersLicensed: z.number().int().min(0).max(1_000_000),
  notes: z.string().max(4000).optional(),
});

function slugify(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "client";
}

export async function saveTenantAction(input: z.input<typeof tenantSchema>, tenantId?: string) {
  const user = await requirePermission("tenants.manage");
  const data = tenantSchema.parse(input);
  const fields = { ...data, contactEmail: data.contactEmail || null, industry: data.industry || null, contactName: data.contactName || null, notes: data.notes || null };
  let saved;
  if (tenantId) {
    saved = await db.tenant.update({ where: { id: tenantId }, data: fields });
  } else {
    let slug = slugify(data.name);
    if (await db.tenant.findUnique({ where: { slug } })) slug = `${slug}-${Math.random().toString(36).slice(2, 6)}`;
    saved = await db.tenant.create({ data: { ...fields, slug, aiAutonomyCap: planFor(data.plan).defaultAutonomyCap } });
  }
  await logAction({ actorId: user.id, action: tenantId ? "tenant.updated" : "tenant.created", detail: { tenantId: saved.id, name: saved.name, plan: saved.plan, status: saved.status } });
  revalidatePath("/tenants");
  revalidatePath(`/tenants/${saved.id}`);
  return { id: saved.id };
}

// The client's consent for AI containment on their estate. Set by the MSSP
// (tenants.manage) or by the client's own admin.
export async function setAiCapAction(tenantId: string, cap: string) {
  const user = await requireUser();
  const own = user.role === "CLIENT_ADMIN" && user.tenantId === tenantId;
  if (!own && !can(user, "tenants.manage")) throw new Error("Forbidden");
  const value = z.enum(["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"]).parse(cap);
  const before = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { aiAutonomyCap: true } });
  await db.tenant.update({ where: { id: tenantId }, data: { aiAutonomyCap: value } });
  await logAction({ actorId: user.id, action: "tenant.ai_consent_changed", detail: { tenantId, from: before.aiAutonomyCap, to: value, byClient: own } });
  revalidatePath(`/tenants/${tenantId}`);
  revalidatePath("/");
}
