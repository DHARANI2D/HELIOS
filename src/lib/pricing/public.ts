import { defaultQuoteConfig, quoteConfigSchema, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";

// The public estimator's view of pricing. Pure, so the rules can be tested.

// Your prices, never your costs, your margins, or how many cases and
// endpoints your clients have.
export function publicContext(ctx: PricingContext): PricingContext {
  return {
    ...ctx,
    plans: ctx.plans.map((p) => ({ ...p, costPerEndpoint: null })),
    book: Object.fromEntries(
      Object.entries(ctx.book)
        .filter(([key]) => key !== "terms.resale")
        .map(([key, v]) => [key, { price: v.price, cost: null }]),
    ),
    aiBaseline: ctx.aiBaseline ? { ...ctx.aiBaseline, cases: 0, endpoints: 0, runs: 0 } : null,
  };
}

// What a visitor may set. The commercial terms that are the team's to give
// (extra discount, exchange rate, usage overrides) are reset, whatever the
// request says; tax is left to the formal quote.
export function publicConfig(input: QuoteConfig, ctx: Pick<PricingContext, "currencies" | "models" | "plans">): QuoteConfig {
  const cfg = quoteConfigSchema.parse(input);
  const currency = ctx.currencies.find((c) => c.code === cfg.commercial.currency && c.code !== "USD");
  const model = ctx.models.some((m) => m.model === cfg.ai.model) ? cfg.ai.model : defaultQuoteConfig(ctx).ai.model;
  return {
    ...cfg,
    ai: { ...cfg.ai, model, alertsPerMonth: null, inputTokensPerRun: null, outputTokensPerRun: null },
    commercial: { ...cfg.commercial, currency: currency?.code ?? "USD", fxRate: currency?.rate ?? 1, extraDiscountPct: 0, taxPct: 0 },
  };
}
