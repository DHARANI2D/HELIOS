"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { startShadowMode } from "@/lib/shadow/service";
import { logAction } from "@/lib/audit";
import { requirePermission, requireUser } from "@/lib/session";
import { can } from "@/lib/rbac";

const tenantSchema = z.object({
  name: z.string().trim().min(2).max(120),
  industry: z.string().trim().max(80).optional(),
  planId: z.string().nullable(),
  status: z.enum(["ONBOARDING", "ACTIVE", "SUSPENDED"]),
  contactName: z.string().trim().max(120).optional(),
  contactEmail: z.string().trim().email().max(200).optional().or(z.literal("")),
  endpointsLicensed: z.number().int().min(0).max(1_000_000),
  usersLicensed: z.number().int().min(0).max(1_000_000),
  notes: z.string().max(4000).optional(),
  isTest: z.boolean().default(false),
});

function slugify(name: string) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "client";
}

export async function saveTenantAction(input: z.input<typeof tenantSchema>, tenantId?: string) {
  const user = await requirePermission("tenants.manage");
  const data = tenantSchema.parse(input);
  const plan = data.planId ? await db.servicePlan.findUnique({ where: { id: data.planId } }) : null;
  if (data.planId && !plan) throw new Error("Unknown service plan");
  const fields = { ...data, contactEmail: data.contactEmail || null, industry: data.industry || null, contactName: data.contactName || null, notes: data.notes || null };
  let saved;
  if (tenantId) {
    saved = await db.tenant.update({ where: { id: tenantId }, data: fields });
  } else {
    let slug = slugify(data.name);
    if (await db.tenant.findUnique({ where: { slug } })) slug = `${slug}-${Math.random().toString(36).slice(2, 6)}`;
    saved = await db.tenant.create({ data: { ...fields, slug, ...(plan ? { aiAutonomyCap: plan.defaultAutonomyCap } : {}) } });
    // New clients start in shadow mode: the AI observes and earns autonomy.
    await startShadowMode(saved.id, { id: user.id, name: user.name ?? user.email ?? "user" });
  }
  await logAction({ actorId: user.id, action: tenantId ? "tenant.updated" : "tenant.created", detail: { tenantId: saved.id, name: saved.name, plan: plan?.key ?? null, status: saved.status, isTest: saved.isTest } });
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
