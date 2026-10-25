"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { calculateQuote, quoteConfigSchema, type QuoteConfig } from "@/lib/pricing/calculator";
import { PRICE_ITEM_INDEX } from "@/lib/pricing/items";
import { loadPricingContext } from "@/lib/pricing/service";
import { createQuote } from "@/lib/pricing/quotes";
import { runAdvisorAgent, type AiAdvice } from "@/lib/pricing/advisor-agent";
import type { AdvisorGoal } from "@/lib/pricing/advisor";
import { rateLimit } from "@/lib/rate-limit";
import { invalidateCatalog } from "@/lib/integrations/tools";
import { CATEGORIES } from "@/lib/integrations/catalog";
import { CONTROLS } from "@/lib/endpoints/controls";
import { PLAN_FEATURES, SEVERITIES } from "@/lib/plans";

function done(path = "/pricing") {
  revalidatePath(path);
}

// Totals are recomputed on the server from the config and the database, so
// a tampered client can't save a quote with made-up numbers — and a quote
// with prices nobody has set can't be saved at all.
export async function saveQuoteAction(config: QuoteConfig, options: { quoteId?: string; tenantId?: string | null; notes?: string } = {}) {
  const user = await requirePermission("pricing.view");
  const cfg = quoteConfigSchema.parse(config);
  if (!cfg.clientName.trim()) throw new Error("Give the quote a client name");
  const totals = calculateQuote(cfg, await loadPricingContext());
  if (totals.missing.length) throw new Error(`Set these first: ${totals.missing.map((m) => m.label).join("; ")}`);
  const data = {
    clientName: cfg.clientName.trim(),
    tenantId: options.tenantId || null,
    currency: totals.currency,
    config: JSON.parse(JSON.stringify(cfg)),
    totals: JSON.parse(JSON.stringify(totals)),
    notes: options.notes?.slice(0, 4000) || null,
  };
  const quote = options.quoteId
    ? await db.quote.update({ where: { id: options.quoteId }, data })
    : await createQuote({ ...data, createdById: user.id, validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) });
  await logAction({ actorId: user.id, action: options.quoteId ? "quote.updated" : "quote.created", detail: { quoteId: quote.id, reference: quote.reference, monthlyNet: totals.monthlyNet, year1Total: totals.year1Total } });
  done();
  return { id: quote.id, reference: quote.reference };
}

// The stack advisor for a quote being built: the model picks among the
// candidates the rules priced; prices are recalculated in the browser.
export async function adviseStackAction(config: QuoteConfig, goal: AdvisorGoal): Promise<AiAdvice> {
  const user = await requirePermission("pricing.view");
  const cfg = quoteConfigSchema.parse(config);
  const g = z.enum(["balanced", "budget", "protection"]).parse(goal);
  if (!rateLimit(`advice:user:${user.id}`, 20, 10 * 60 * 1000).ok) throw new Error("The advisor has been asked many times in a row; try again in a few minutes");
  return runAdvisorAgent(cfg, await loadPricingContext(), g, { audience: "staff", trigger: "manual", requestedById: user.id });
}

export async function setQuoteStatusAction(quoteId: string, status: string) {
  const user = await requirePermission("pricing.view");
  const value = z.enum(["DRAFT", "SENT", "ACCEPTED", "LOST"]).parse(status);
  await db.quote.update({ where: { id: quoteId }, data: { status: value } });
  await logAction({ actorId: user.id, action: "quote.status_changed", detail: { quoteId, status: value } });
  done();
}

// --- price book

const money = z.number().min(0).max(10_000_000).nullable();

export async function savePriceAction(itemKey: string, price: number | null, cost: number | null) {
  const user = await requirePermission("pricing.manage");
  const def = PRICE_ITEM_INDEX.get(itemKey);
  if (!def) throw new Error("Unknown price item");
  const p = money.parse(price);
  const c = def.hasCost ? money.parse(cost) : null;
  if (def.unit === "percent" && p != null && p > 100) throw new Error("A percentage can't exceed 100");
  if (def.unit === "ratio" && p != null && p > 1) throw new Error("A ratio is between 0 and 1");
  await db.priceItem.upsert({
    where: { key: itemKey },
    update: { price: p, cost: c, updatedById: user.id },
    create: { key: itemKey, group: def.group, label: def.label, unit: def.unit, note: def.note ?? null, price: p, cost: c, updatedById: user.id },
  });
  await logAction({ actorId: user.id, action: "pricing.price_changed", detail: { itemKey, price: p, cost: c } });
  done();
}

// --- service plans

const minutes = z.number().int().min(1).max(525_600).nullable();
const planSchema = z.object({
  key: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9-]{1,40}$/, "Key: lowercase letters, digits and dashes"),
  name: z.string().trim().min(2).max(80),
  tagline: z.string().trim().max(160).nullable(),
  coverage: z.string().trim().min(1).max(20),
  ackMinutes: z.record(z.enum(SEVERITIES as [string, ...string[]]), minutes),
  containMinutes: z.record(z.enum(SEVERITIES as [string, ...string[]]), minutes),
  irRetainerHours: z.number().int().min(0).max(10_000),
  pricePerEndpoint: money,
  costPerEndpoint: money,
  onboardingMinimum: money,
  defaultAutonomyCap: z.enum(["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"]),
  features: z.record(z.enum(PLAN_FEATURES as [string, ...string[]]), z.union([z.boolean(), z.string().trim().max(80)])),
  active: z.boolean(),
  sortOrder: z.number().int().min(0).max(1000),
});
export type PlanInput = z.infer<typeof planSchema>;

export async function savePlanAction(input: PlanInput, planId?: string) {
  const user = await requirePermission("pricing.manage");
  const data = planSchema.parse(input);
  const clash = await db.servicePlan.findFirst({ where: { key: data.key, ...(planId ? { id: { not: planId } } : {}) } });
  if (clash) throw new Error(`Another plan already uses the key "${data.key}"`);
  const saved = planId ? await db.servicePlan.update({ where: { id: planId }, data }) : await db.servicePlan.create({ data });
  await logAction({ actorId: user.id, action: planId ? "plan.updated" : "plan.created", detail: { planId: saved.id, key: saved.key, name: saved.name, pricePerEndpoint: saved.pricePerEndpoint } });
  done();
  revalidatePath("/tenants");
  return { id: saved.id };
}

// Plans with clients are retired (inactive), not deleted, so the clients keep
// their SLA.
export async function deletePlanAction(planId: string) {
  const user = await requirePermission("pricing.manage");
  const plan = await db.servicePlan.findUniqueOrThrow({ where: { id: planId }, include: { _count: { select: { tenants: true } } } });
  if (plan._count.tenants > 0) {
    await db.servicePlan.update({ where: { id: planId }, data: { active: false } });
    await logAction({ actorId: user.id, action: "plan.retired", detail: { planId, key: plan.key, tenants: plan._count.tenants } });
  } else {
    await db.servicePlan.delete({ where: { id: planId } });
    await logAction({ actorId: user.id, action: "plan.deleted", detail: { planId, key: plan.key } });
  }
  done();
  return { retired: plan._count.tenants > 0 };
}

// --- tool catalog

export async function saveToolPriceAction(toolKey: string, customPrice: number | null, active: boolean) {
  const user = await requirePermission("pricing.manage");
  const price = money.parse(customPrice);
  await db.catalogTool.update({ where: { key: toolKey }, data: { customPrice: price, active: z.boolean().parse(active) } });
  invalidateCatalog();
  await logAction({ actorId: user.id, action: "catalog.tool_price_changed", detail: { toolKey, customPrice: price, active } });
  done();
  revalidatePath("/integrations");
}

const ACTION_TYPES = ["ISOLATE_HOST", "RELEASE_HOST", "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER", "ENABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE", "BLOCK_SENDER", "CREATE_TICKET", "NOTIFY_SLACK"] as const;
const toolSchema = z.object({
  key: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9_]{1,60}$/, "Key: lowercase letters, digits and underscores"),
  name: z.string().trim().min(2).max(80),
  vendor: z.string().trim().min(1).max(60),
  category: z.enum(CATEGORIES.map((c) => c.key) as [string, ...string[]]),
  description: z.string().trim().min(3).max(400),
  controls: z.array(z.enum(CONTROLS.map((c) => c.key) as [string, ...string[]])).max(20),
  actions: z.array(z.enum(ACTION_TYPES)).max(20),
  ingest: z.enum(["crowdstrike", "defender", "sentinelone", "wazuh", "entra", "okta", "generic"]).nullable(),
  platforms: z.array(z.string().trim().min(1).max(40)).max(12),
  deployment: z.enum(["cloud", "self-hosted", "hybrid"]),
  offlineCapable: z.boolean(),
  priceUnit: z.enum(["endpoint", "user", "server", "gb", "flat"]),
  customPrice: money,
});
export type CustomToolInput = z.infer<typeof toolSchema>;

// Tools not in the seeded catalog — a regional vendor, your own service.
export async function addCatalogToolAction(input: CustomToolInput) {
  const user = await requirePermission("pricing.manage");
  const data = toolSchema.parse(input);
  if (await db.catalogTool.findUnique({ where: { key: data.key } })) throw new Error(`A tool with key "${data.key}" already exists`);
  await db.catalogTool.create({ data: { ...data, listPrice: null, priceSource: "Added by your team", active: true } });
  invalidateCatalog();
  await logAction({ actorId: user.id, action: "catalog.tool_added", detail: { toolKey: data.key, name: data.name, vendor: data.vendor } });
  done();
  revalidatePath("/integrations");
}

// --- volume discounts, currencies, model prices

export async function saveVolumeTierAction(minEndpoints: number, discountPct: number) {
  const user = await requirePermission("pricing.manage");
  const min = z.number().int().min(1).max(10_000_000).parse(minEndpoints);
  const pct = z.number().min(0).max(90).parse(discountPct);
  await db.volumeDiscount.upsert({ where: { minEndpoints: min }, update: { discountPct: pct }, create: { minEndpoints: min, discountPct: pct } });
  await logAction({ actorId: user.id, action: "pricing.volume_tier_saved", detail: { minEndpoints: min, discountPct: pct } });
  done();
}

export async function deleteVolumeTierAction(minEndpoints: number) {
  const user = await requirePermission("pricing.manage");
  await db.volumeDiscount.deleteMany({ where: { minEndpoints } });
  await logAction({ actorId: user.id, action: "pricing.volume_tier_deleted", detail: { minEndpoints } });
  done();
}

export async function saveCurrencyAction(code: string, symbol: string, rate: number) {
  const user = await requirePermission("pricing.manage");
  const c = z.string().trim().toUpperCase().regex(/^[A-Z]{3}$/, "Use the ISO 4217 code").parse(code);
  if (c === "USD") throw new Error("USD is the base currency; its rate is always 1");
  try {
    new Intl.NumberFormat("en-US", { style: "currency", currency: c });
  } catch {
    throw new Error(`${c} isn't a currency code`);
  }
  const s = z.string().trim().min(1).max(6).parse(symbol);
  const r = z.number().positive().max(1_000_000).parse(rate);
  await db.currency.upsert({ where: { code: c }, update: { symbol: s, rate: r, updatedById: user.id }, create: { code: c, symbol: s, rate: r, updatedById: user.id } });
  await logAction({ actorId: user.id, action: "pricing.currency_saved", detail: { code: c, rate: r } });
  done();
}

export async function deleteCurrencyAction(code: string) {
  const user = await requirePermission("pricing.manage");
  if (code === "USD") throw new Error("USD is the base currency");
  await db.currency.deleteMany({ where: { code } });
  await logAction({ actorId: user.id, action: "pricing.currency_deleted", detail: { code } });
  done();
}

export async function saveModelPriceAction(input: { model: string; provider: string; inputPer: number; outputPer: number; source: string | null }) {
  const user = await requirePermission("pricing.manage");
  const data = z
    .object({
      model: z.string().trim().min(2).max(120),
      provider: z.string().trim().min(1).max(60),
      inputPer: z.number().min(0).max(10_000),
      outputPer: z.number().min(0).max(10_000),
      source: z.string().trim().max(200).nullable(),
    })
    .parse(input);
  await db.aiModelPrice.upsert({ where: { model: data.model }, update: data, create: data });
  await logAction({ actorId: user.id, action: "pricing.model_price_saved", detail: data });
  done();
  revalidatePath("/ai");
}

export async function deleteModelPriceAction(model: string) {
  const user = await requirePermission("pricing.manage");
  await db.aiModelPrice.deleteMany({ where: { model } });
  await logAction({ actorId: user.id, action: "pricing.model_price_deleted", detail: { model } });
  done();
}
