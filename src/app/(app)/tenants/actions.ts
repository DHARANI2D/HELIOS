"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { startShadowMode } from "@/lib/shadow/service";
import { goLiveBlockers } from "@/lib/ingest/health";
import { logAction } from "@/lib/audit";
import { requirePermission, requireUser } from "@/lib/session";
import { can } from "@/lib/rbac";
import { requestChange } from "@/lib/changes/service";
import { autonomyWidens, changeActorOf } from "@/lib/changes/rules";
import { AUTONOMY_LABEL } from "@/lib/ai/catalog";
import { action } from "@/lib/action";

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

export const saveTenantAction = action(async function saveTenantAction(input: z.input<typeof tenantSchema>, tenantId?: string) {
  const user = await requirePermission("tenants.manage");
  const data = tenantSchema.parse(input);
  const plan = data.planId ? await db.servicePlan.findUnique({ where: { id: data.planId } }) : null;
  if (data.planId && !plan) throw new Error("Unknown service plan");
  const fields = { ...data, contactEmail: data.contactEmail || null, industry: data.industry || null, contactName: data.contactName || null, notes: data.notes || null };
  let saved;
  if (tenantId) {
    // Going live needs every log source sending: a pilot can't start with dead sources.
    const before = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { status: true } });
    if (data.status === "ACTIVE" && before.status !== "ACTIVE") {
      const blockers = await goLiveBlockers(tenantId);
      if (blockers.length) throw new Error(`Not ready to go live: ${blockers.join("; ")}`);
    }
    saved = await db.tenant.update({ where: { id: tenantId }, data: fields });
  } else {
    if (data.status === "ACTIVE") throw new Error("A new client starts in onboarding: it goes live once its log sources are sending");
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
});

// The client's consent for AI containment on their estate. Lowering it
// applies at once (it only takes power away from the AI). Raising it is a
// rule change: it takes effect once the client and HELIOS have approved it
// (lib/changes). Asked for by the MSSP (tenants.manage) or the client admin.
export const setAiCapAction = action(async function setAiCapAction(tenantId: string, cap: string, reason?: string) {
  const user = await requireUser();
  const own = user.role === "CLIENT_ADMIN" && user.tenantId === tenantId;
  if (!own && !can(user, "tenants.manage")) throw new Error("Forbidden");
  const value = z.enum(["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"]).parse(cap);
  const before = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { aiAutonomyCap: true, name: true } });
  if (before.aiAutonomyCap === value) return { pending: false };
  if (autonomyWidens(before.aiAutonomyCap, value)) {
    await requestChange(
      { tenantId, kind: "AI_CONSENT", summary: `AI containment consent for ${before.name}: ${AUTONOMY_LABEL[before.aiAutonomyCap]} → ${AUTONOMY_LABEL[value]}`, reason: String(reason ?? "").trim() || "Allow HELIOS's AI to do more on the estate", payload: { from: before.aiAutonomyCap, to: value } },
      changeActorOf(user),
    );
    revalidatePath(`/tenants/${tenantId}`);
    revalidatePath("/changes");
    return { pending: true };
  }
  await db.tenant.update({ where: { id: tenantId }, data: { aiAutonomyCap: value } });
  await logAction({ actorId: user.id, action: "tenant.ai_consent_changed", detail: { tenantId, from: before.aiAutonomyCap, to: value, byClient: own } });
  revalidatePath(`/tenants/${tenantId}`);
  revalidatePath("/");
  return { pending: false };
});

// A client's own data key: rotate it (credentials re-sealed), or destroy it
// when offboarding a suspended client (its stored credentials become unreadable).
export const rotateTenantKeyAction = action(async function rotateTenantKeyAction(tenantId: string) {
  const user = await requirePermission("tenants.manage");
  if (user.role !== "ADMIN") throw new Error("Forbidden: admin role required");
  const { rotateTenantKey } = await import("@/lib/keys");
  const r = await rotateTenantKey(tenantId, user.id);
  revalidatePath(`/tenants/${tenantId}`);
  return r;
});

export const destroyTenantKeysAction = action(async function destroyTenantKeysAction(tenantId: string, confirmName: string) {
  const user = await requirePermission("tenants.manage");
  if (user.role !== "ADMIN") throw new Error("Forbidden: admin role required");
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { name: true } });
  if (confirmName.trim() !== tenant.name) throw new Error("Type the client's name exactly to confirm");
  const { destroyTenantKeys } = await import("@/lib/keys");
  const r = await destroyTenantKeys(tenantId, user.id);
  revalidatePath(`/tenants/${tenantId}`);
  return r;
});
