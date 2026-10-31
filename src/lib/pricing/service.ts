import { db } from "@/lib/db";
import { listPlans } from "@/lib/service-plans";
import { listCatalogTools } from "@/lib/integrations/tools";
import type { AiBaseline, PricingContext } from "@/lib/pricing/calculator";
import type { PriceBook } from "@/lib/pricing/items";

// Everything the calculator prices with, from the database.

const BASELINE_DAYS = 90;

export async function loadPriceBook(): Promise<PriceBook> {
  const rows = await db.priceItem.findMany();
  return Object.fromEntries(rows.map((r) => [r.key, { price: r.price, cost: r.cost }]));
}

export async function loadModelPrices() {
  return db.aiModelPrice.findMany({ orderBy: [{ provider: "asc" }, { inputPer: "desc" }] });
}

// Prompt-cache pricing relative to the input price: writing a 5-minute
// cache entry costs 1.25×, reading one 0.1× (Anthropic's published rates;
// OpenAI-style automatic caching reports reads only).
export const CACHE_WRITE_RATE = 1.25;
export const CACHE_READ_RATE = 0.1;

// Claude in Amazon Bedrock names models anthropic.claude-… (optionally with
// a cross-region prefix such as global. or apac.); they're priced as the
// same model.
export const priceKey = (model: string) => model.replace(/^(?:[a-z]{2,6}\.)?anthropic\./, "");

export interface RunUsage {
  model: string | null;
  inputTokens: number | null;
  outputTokens: number | null;
  cacheReadTokens?: number | null;
  cacheWriteTokens?: number | null;
}

// One run's USD cost at a model's prices. inputTokens counts every input
// token; the cached share is priced at the cache rates instead.
export function runCost(r: RunUsage, p: { inputPer: number; outputPer: number }) {
  const read = r.cacheReadTokens ?? 0;
  const write = r.cacheWriteTokens ?? 0;
  const plain = Math.max(0, (r.inputTokens ?? 0) - read - write);
  return (plain * p.inputPer + write * p.inputPer * CACHE_WRITE_RATE + read * p.inputPer * CACHE_READ_RATE + (r.outputTokens ?? 0) * p.outputPer) / 1_000_000;
}

// USD cost of AI runs at the stored model prices; runs on models without a
// price (local models, or ones nobody priced) count as zero.
export async function aiCostOf(runs: RunUsage[]) {
  const prices = new Map((await loadModelPrices()).map((p) => [p.model, p]));
  return runs.reduce((sum, r) => {
    const p = r.model ? (prices.get(r.model) ?? prices.get(priceKey(r.model))) : undefined;
    return p ? sum + runCost(r, p) : sum;
  }, 0);
}

// How much AI work a client generates, measured from the last 90 days of
// client cases and AI runs. Null fields mean there isn't history yet; the
// configurator then asks for the figure instead of guessing it.
export async function aiUsageBaseline(now = new Date()): Promise<AiBaseline> {
  const since = new Date(now.getTime() - BASELINE_DAYS * 24 * 60 * 60 * 1000);
  const [cases, licensed, inventory, runs] = await Promise.all([
    db.case.count({ where: { tenantId: { not: null }, createdAt: { gte: since } } }),
    db.tenant.aggregate({ where: { status: "ACTIVE" }, _sum: { endpointsLicensed: true } }),
    db.endpoint.count({ where: { tenantId: { not: null } } }),
    db.aiRun.findMany({
      // Case agents only: stack-advisor runs aren't driven by alerts.
      where: { createdAt: { gte: since }, status: "succeeded", model: { not: null }, inputTokens: { gt: 0 }, caseId: { not: null } },
      select: { caseId: true, inputTokens: true, outputTokens: true },
    }),
  ]);
  const endpoints = Math.max(licensed._sum.endpointsLicensed ?? 0, inventory);
  const casesWithRuns = new Set(runs.map((r) => r.caseId).filter(Boolean)).size;
  const avg = (xs: number[]) => (xs.length ? Math.round(xs.reduce((s, x) => s + x, 0) / xs.length) : null);
  return {
    days: BASELINE_DAYS,
    cases,
    endpoints,
    casesPerEndpointMonth: cases > 0 && endpoints > 0 ? cases / endpoints / (BASELINE_DAYS / 30) : null,
    runs: runs.length,
    runsPerCase: casesWithRuns > 0 ? runs.length / casesWithRuns : null,
    inputTokensPerRun: avg(runs.map((r) => r.inputTokens ?? 0)),
    outputTokensPerRun: avg(runs.map((r) => r.outputTokens ?? 0)),
  };
}

export async function loadPricingContext(): Promise<PricingContext> {
  const [plans, tools, book, volume, models, currencies, aiBaseline] = await Promise.all([
    listPlans(),
    listCatalogTools(),
    loadPriceBook(),
    db.volumeDiscount.findMany({ orderBy: { minEndpoints: "asc" } }),
    loadModelPrices(),
    db.currency.findMany({ orderBy: { code: "asc" } }),
    aiUsageBaseline(),
  ]);
  return {
    plans,
    tools,
    book,
    volumeTiers: volume.map((v) => ({ minEndpoints: v.minEndpoints, discountPct: v.discountPct })),
    models: models.map((m) => ({ model: m.model, provider: m.provider, inputPer: m.inputPer, outputPer: m.outputPer })),
    currencies: currencies.map((c) => ({ code: c.code, symbol: c.symbol, rate: c.rate })),
    aiBaseline,
  };
}
