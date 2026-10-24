"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { calculateQuote, quoteConfigSchema, type QuoteConfig } from "@/lib/pricing/calculator";
import { PRICE_ITEMS } from "@/lib/pricing/catalog";
import { TOOLS } from "@/lib/integrations/catalog";
import { loadPriceBook } from "@/lib/pricing/service";

async function nextReference() {
  const year = new Date().getUTCFullYear();
  const count = await db.quote.count({ where: { reference: { startsWith: `Q-${year}-` } } });
  return `Q-${year}-${String(count + 1).padStart(4, "0")}`;
}

// Totals are recomputed on the server from the config and the price book,
// so a tampered client can't save a quote with made-up numbers.
export async function saveQuoteAction(config: QuoteConfig, options: { quoteId?: string; tenantId?: string | null; notes?: string } = {}) {
  const user = await requirePermission("pricing.view");
  const cfg = quoteConfigSchema.parse(config);
  if (!cfg.clientName.trim()) throw new Error("Give the quote a client name");
  const totals = calculateQuote(cfg, await loadPriceBook());
  const data = {
    clientName: cfg.clientName.trim(),
    tenantId: options.tenantId || null,
    currency: cfg.commercial.currency,
    config: JSON.parse(JSON.stringify(cfg)),
    totals: JSON.parse(JSON.stringify(totals)),
    notes: options.notes?.slice(0, 4000) || null,
  };
  const quote = options.quoteId
    ? await db.quote.update({ where: { id: options.quoteId }, data })
    : await db.quote.create({ data: { ...data, reference: await nextReference(), createdById: user.id, validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) } });
  await logAction({ actorId: user.id, action: options.quoteId ? "quote.updated" : "quote.created", detail: { quoteId: quote.id, reference: quote.reference, monthlyNet: totals.monthlyNet, year1Total: totals.year1Total } });
  revalidatePath("/pricing");
  return { id: quote.id, reference: quote.reference };
}

export async function setQuoteStatusAction(quoteId: string, status: string) {
  const user = await requirePermission("pricing.view");
  const value = z.enum(["DRAFT", "SENT", "ACCEPTED", "LOST"]).parse(status);
  await db.quote.update({ where: { id: quoteId }, data: { status: value } });
  await logAction({ actorId: user.id, action: "quote.status_changed", detail: { quoteId, status: value } });
  revalidatePath("/pricing");
}

const VALID_KEYS = new Set([...PRICE_ITEMS.map((i) => i.key), ...TOOLS.map((t) => `tool.${t.key}`)]);

export async function savePriceAction(itemKey: string, unitPrice: number, unitCost: number | null) {
  const user = await requirePermission("pricing.manage");
  if (!VALID_KEYS.has(itemKey)) throw new Error("Unknown price item");
  const price = z.number().min(0).max(10_000_000).parse(unitPrice);
  const cost = unitCost == null ? null : z.number().min(0).max(10_000_000).parse(unitCost);
  await db.priceOverride.upsert({ where: { itemKey }, update: { unitPrice: price, unitCost: cost, updatedById: user.id }, create: { itemKey, unitPrice: price, unitCost: cost, updatedById: user.id } });
  await logAction({ actorId: user.id, action: "pricing.price_changed", detail: { itemKey, unitPrice: price, unitCost: cost } });
  revalidatePath("/pricing");
}

export async function resetPriceAction(itemKey: string) {
  const user = await requirePermission("pricing.manage");
  await db.priceOverride.deleteMany({ where: { itemKey } });
  await logAction({ actorId: user.id, action: "pricing.price_reset", detail: { itemKey } });
  revalidatePath("/pricing");
}
