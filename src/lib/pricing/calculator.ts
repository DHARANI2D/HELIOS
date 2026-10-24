import { z } from "zod";

import { hasFeature, type ServicePlan } from "@/lib/plans";
import { CATEGORIES, toolLabel, toolUnitPrice, type ToolDefinition } from "@/lib/integrations/catalog";
import { CONTROLS, type ProtectionControl } from "@/lib/endpoints/controls";
import { PRICE_ITEM_INDEX, type PriceBook } from "@/lib/pricing/items";

// Build & Price: turns a client profile + chosen stack into a priced quote.
// Pure and deterministic (no I/O): every price comes in through the
// PricingContext loaded from the database, so the configurator recalculates
// live in the browser and the server re-derives the same totals on save.
// Nothing is assumed — a price the quote needs but nobody has set is
// reported in `missing` and the quote can't be saved until it's filled in.

export const quoteConfigSchema = z.object({
  clientName: z.string().max(120).default(""),
  profile: z.object({
    workstations: z.number().int().min(0).max(1_000_000).default(0),
    servers: z.number().int().min(0).max(100_000).default(0),
    users: z.number().int().min(0).max(1_000_000).default(0),
    logGbPerDay: z.number().min(0).max(100_000).default(0),
  }),
  plan: z.string().max(64).default(""), // service plan key
  // Per category: a tool key, "byo" (client already licenses one), or "none".
  tools: z.record(z.string(), z.string()).default({}),
  ai: z.object({
    mode: z.enum(["none", "cloud", "local"]).default("none"),
    model: z.string().max(120).default(""),
    hardware: z.enum(["workstation", "server", "cluster"]).default("server"),
    // Overrides for the usage estimate; null = derive from your case history.
    alertsPerMonth: z.number().int().min(0).max(10_000_000).nullable().default(null),
    inputTokensPerRun: z.number().int().min(0).max(10_000_000).nullable().default(null),
    outputTokensPerRun: z.number().int().min(0).max(10_000_000).nullable().default(null),
  }),
  services: z.object({
    irExtraHours: z.number().int().min(0).max(10_000).default(0),
    pentests: z.number().int().min(0).max(100).default(0),
    trainingSessions: z.number().int().min(0).max(100).default(0),
    compliance: z.boolean().default(false),
    dedicatedAnalyst: z.boolean().default(false),
    premiumSupport: z.boolean().default(false),
  }),
  commercial: z.object({
    term: z.enum(["monthly", "annual", "3year"]).default("monthly"),
    currency: z.string().max(8).default("USD"),
    fxRate: z.number().positive().default(1),
    extraDiscountPct: z.number().min(0).max(50).default(0),
    taxPct: z.number().min(0).max(40).default(0),
  }),
});

export type QuoteConfig = z.infer<typeof quoteConfigSchema>;

// AI usage measured from this platform's own history (src/lib/pricing/service.ts).
export interface AiBaseline {
  days: number;
  cases: number;
  endpoints: number;
  casesPerEndpointMonth: number | null;
  runs: number;
  runsPerCase: number | null;
  inputTokensPerRun: number | null;
  outputTokensPerRun: number | null;
}

export interface PricingContext {
  plans: ServicePlan[];
  tools: ToolDefinition[];
  book: PriceBook;
  volumeTiers: Array<{ minEndpoints: number; discountPct: number }>;
  models: Array<{ model: string; provider: string; inputPer: number; outputPer: number }>;
  currencies: Array<{ code: string; symbol: string; rate: number }>;
  aiBaseline: AiBaseline | null;
}

export function defaultQuoteConfig(ctx: Pick<PricingContext, "plans" | "models">): QuoteConfig {
  return quoteConfigSchema.parse({
    profile: {},
    // The platform's default model when it has a price, else the first priced one.
    ai: { model: (ctx.models.find((m) => m.model === "claude-opus-5-5") ?? ctx.models[0])?.model ?? "" },
    services: {},
    commercial: {},
    plan: ctx.plans[0]?.key ?? "",
  });
}

export type LineKind = "service" | "license" | "ai" | "services";

export interface QuoteLine {
  key: string;
  kind: LineKind;
  label: string;
  detail: string;
  monthly: number; // USD, before term discounts
  oneTime: number; // USD
  costMonthly: number;
  costOneTime: number;
  // list: vendor list price · custom: your price · estimate: usage-based · missing: no price set
  basis?: "list" | "custom" | "estimate" | "missing";
}

export interface MissingPrice {
  key: string;
  label: string;
  fix: "plan" | "price-book" | "tool" | "ai-usage" | "model" | "currency";
}

export interface QuoteResult {
  // The plan as it stood when priced, so a saved quote doesn't change when
  // the plan is edited later.
  plan: Pick<ServicePlan, "key" | "name" | "tagline" | "coverage" | "ackMinutes" | "irRetainerHours"> | null;
  lines: QuoteLine[];
  endpoints: number;
  monthlyGross: number;
  volumeDiscount: number;
  volumeDiscountPct: number;
  termDiscount: number;
  termDiscountPct: number;
  extraDiscount: number;
  monthlyNet: number;
  annualRecurring: number;
  oneTime: number;
  amcAnnual: number;
  amcMonthly: number;
  tax: number; // on year-1
  year1Total: number;
  threeYearTotal: number;
  perEndpointMonthly: number;
  perUserMonthly: number;
  costMonthly: number;
  costYear1: number;
  grossMarginPct: number | null;
  // Costs that weren't set, so the margin is understated or unknown.
  costIncomplete: boolean;
  coverage: Array<{ control: ProtectionControl; covered: boolean; by: string[]; essential: boolean }>;
  gaps: ProtectionControl[];
  missing: MissingPrice[];
  aiUsage: { alertsPerMonth: number; runsPerMonth: number; tokensPerMonth: number; modelCostMonthly: number; source: "history" | "entered" } | null;
  currency: string;
  fxRate: number;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

function toolUnits(tool: ToolDefinition, cfg: QuoteConfig) {
  const endpoints = cfg.profile.workstations + cfg.profile.servers;
  switch (tool.price.unit) {
    case "endpoint":
      return { qty: endpoints, label: `${endpoints} endpoints` };
    case "user":
      return { qty: cfg.profile.users, label: `${cfg.profile.users} users` };
    case "server":
      return { qty: cfg.profile.servers, label: `${cfg.profile.servers} servers` };
    case "gb":
      return { qty: Math.round(cfg.profile.logGbPerDay * 30), label: `${Math.round(cfg.profile.logGbPerDay * 30)} GB/month` };
    case "flat":
      return { qty: 1, label: "flat" };
  }
}

export function toolMonthlyPrice(tool: ToolDefinition, cfg: QuoteConfig) {
  const unitPrice = toolUnitPrice(tool);
  const { qty, label } = toolUnits(tool, cfg);
  return { monthly: unitPrice == null ? null : round2(unitPrice * qty), unitPrice, qty, label };
}

export function calculateQuote(input: QuoteConfig, ctx: PricingContext): QuoteResult {
  const cfg = quoteConfigSchema.parse(input);
  const missing: MissingPrice[] = [];
  let costIncomplete = false;
  const need = (key: string) => {
    const v = ctx.book[key]?.price;
    if (v == null) {
      if (!missing.some((m) => m.key === key)) missing.push({ key, label: PRICE_ITEM_INDEX.get(key)?.label ?? key, fix: "price-book" });
      return 0;
    }
    return v;
  };
  const costOf = (key: string) => {
    const c = ctx.book[key]?.cost;
    if (c == null) {
      if (PRICE_ITEM_INDEX.get(key)?.hasCost) costIncomplete = true;
      return 0;
    }
    return c;
  };

  const plan = ctx.plans.find((p) => p.key === cfg.plan) ?? null;
  const endpoints = cfg.profile.workstations + cfg.profile.servers;
  const lines: QuoteLine[] = [];

  // --- managed service
  if (!plan) {
    missing.push({ key: "plan", label: ctx.plans.length ? "Choose a service plan" : "Define a service plan (Build & Price → Service plans)", fix: "plan" });
  } else {
    const perEndpoint = plan.pricePerEndpoint;
    if (perEndpoint == null) missing.push({ key: `plan.${plan.key}`, label: `${plan.name}: price per endpoint`, fix: "plan" });
    if (plan.costPerEndpoint == null) costIncomplete = true;
    lines.push({
      key: "service.plan",
      kind: "service",
      label: `${plan.name} (${plan.coverage})`,
      detail: perEndpoint == null ? `${endpoints} endpoints × price not set` : `${endpoints} endpoints × ${perEndpoint.toFixed(2)}`,
      monthly: round2(endpoints * (perEndpoint ?? 0)),
      oneTime: 0,
      costMonthly: round2(endpoints * (plan.costPerEndpoint ?? 0)),
      costOneTime: 0,
      basis: perEndpoint == null ? "missing" : undefined,
    });
  }
  if (cfg.profile.servers > 0) {
    const p = need("svc.server");
    lines.push({ key: "service.server", kind: "service", label: "Server monitoring", detail: `${cfg.profile.servers} servers × ${p.toFixed(2)}`, monthly: round2(cfg.profile.servers * p), oneTime: 0, costMonthly: round2(cfg.profile.servers * costOf("svc.server")), costOneTime: 0 });
  }
  if (cfg.profile.users > 0) {
    const p = need("svc.identity");
    lines.push({ key: "service.identity", kind: "service", label: "Identity & email monitoring", detail: `${cfg.profile.users} users × ${p.toFixed(2)}`, monthly: round2(cfg.profile.users * p), oneTime: 0, costMonthly: round2(cfg.profile.users * costOf("svc.identity")), costOneTime: 0 });
  }
  if (cfg.services.compliance && !(plan && hasFeature(plan, "compliance"))) {
    lines.push({ key: "service.compliance", kind: "service", label: "Compliance evidence packs", detail: "monthly", monthly: need("svc.compliance"), oneTime: 0, costMonthly: costOf("svc.compliance"), costOneTime: 0 });
  }
  if (cfg.services.dedicatedAnalyst && !(plan && plan.features.dedicatedAnalyst === true)) {
    lines.push({ key: "service.dedicated", kind: "service", label: "Named lead analyst", detail: "monthly", monthly: need("svc.dedicated"), oneTime: 0, costMonthly: costOf("svc.dedicated"), costOneTime: 0 });
  }

  // --- tool licences, resold at your price; you buy at the resale ratio
  const selectedTools: ToolDefinition[] = [];
  let toolsToOnboard = 0;
  let resold = false;
  for (const category of CATEGORIES.filter((c) => c.priced)) {
    const choice = cfg.tools[category.key];
    if (!choice || choice === "none") continue;
    toolsToOnboard++;
    if (choice === "byo") {
      lines.push({ key: `license.${category.key}`, kind: "license", label: `${category.label}: client's existing tool`, detail: "no licence resold", monthly: 0, oneTime: 0, costMonthly: 0, costOneTime: 0 });
      continue;
    }
    const tool = ctx.tools.find((t) => t.key === choice);
    if (!tool || tool.category !== category.key) continue;
    selectedTools.push(tool);
    const { monthly, unitPrice, label } = toolMonthlyPrice(tool, cfg);
    if (monthly == null) missing.push({ key: `tool.${tool.key}`, label: `${toolLabel(tool)}: your price (${tool.price.source ?? "sold by quote"})`, fix: "tool" });
    if (monthly) resold = true;
    lines.push({
      key: `license.${tool.key}`,
      kind: "license",
      label: toolLabel(tool),
      detail: monthly == null ? `${label} × price not set` : unitPrice ? `${label} × ${unitPrice.toFixed(2)}` : "no licence fee",
      monthly: monthly ?? 0,
      oneTime: 0,
      costMonthly: 0, // filled in below once the resale ratio is known
      costOneTime: 0,
      basis: monthly == null ? "missing" : tool.price.custom != null ? "custom" : "list",
    });
  }
  if (resold) {
    const ratio = ctx.book["terms.resale"]?.price;
    if (ratio == null) costIncomplete = true;
    for (const l of lines) if (l.kind === "license") l.costMonthly = round2(l.monthly * (ratio ?? 0));
  }

  // --- AI
  let aiUsage: QuoteResult["aiUsage"] = null;
  if (cfg.ai.mode === "cloud") {
    const base = ctx.aiBaseline;
    const estAlerts = base?.casesPerEndpointMonth != null ? Math.round(endpoints * base.casesPerEndpointMonth) : null;
    const alerts = cfg.ai.alertsPerMonth ?? estAlerts;
    const inTok = cfg.ai.inputTokensPerRun ?? base?.inputTokensPerRun ?? null;
    const outTok = cfg.ai.outputTokensPerRun ?? base?.outputTokensPerRun ?? null;
    const runsPerCase = base?.runsPerCase ?? 1;
    const model = ctx.models.find((m) => m.model === cfg.ai.model);
    if (alerts == null) missing.push({ key: "ai.alerts", label: "Expected alerts per month (no case history to estimate from yet)", fix: "ai-usage" });
    if (inTok == null || outTok == null) missing.push({ key: "ai.tokens", label: "Tokens per AI run (no AI run history to measure yet)", fix: "ai-usage" });
    if (!model) missing.push({ key: "ai.model", label: cfg.ai.model ? `Model price for ${cfg.ai.model}` : "Choose a model", fix: "model" });
    const platform = need("ai.cloud.platform");
    const markup = need("ai.cloud.markup") / 100;
    const runs = Math.round((alerts ?? 0) * runsPerCase);
    const tokensIn = runs * (inTok ?? 0);
    const tokensOut = runs * (outTok ?? 0);
    const modelCost = model ? (tokensIn * model.inputPer + tokensOut * model.outputPer) / 1_000_000 : 0;
    aiUsage = { alertsPerMonth: alerts ?? 0, runsPerMonth: runs, tokensPerMonth: Math.round(tokensIn + tokensOut), modelCostMonthly: round2(modelCost), source: cfg.ai.alertsPerMonth != null || cfg.ai.inputTokensPerRun != null ? "entered" : "history" };
    lines.push({
      key: "ai.cloud",
      kind: "ai",
      label: "AI first response · cloud",
      detail: `${endpoints} endpoints × ${platform.toFixed(2)} + ~${runs.toLocaleString("en-US")} AI runs/month on ${cfg.ai.model || "—"}`,
      monthly: round2(endpoints * platform + modelCost * (1 + markup)),
      oneTime: 0,
      costMonthly: round2(endpoints * costOf("ai.cloud.platform") + modelCost),
      costOneTime: 0,
      basis: "estimate",
    });
  } else if (cfg.ai.mode === "local") {
    const hw = `ai.local.${cfg.ai.hardware}`;
    lines.push({
      key: "ai.local",
      kind: "ai",
      label: "AI first response · local / offline",
      detail: `${cfg.ai.hardware} hardware + setup, hosting monthly; no per-alert model cost`,
      monthly: need("ai.local.hosting"),
      oneTime: round2(need(hw) + need("ai.local.setup")),
      costMonthly: costOf("ai.local.hosting"),
      costOneTime: round2(costOf(hw) + costOf("ai.local.setup")),
    });
  }

  // --- onboarding & professional services
  if (endpoints > 0 || toolsToOnboard > 0) {
    const raw = (endpoints > 0 ? endpoints * need("onb.endpoint") : 0) + (toolsToOnboard > 0 ? toolsToOnboard * need("onb.tool") : 0);
    const minimum = plan?.onboardingMinimum ?? 0;
    const onboarding = Math.max(raw, minimum);
    lines.push({
      key: "onetime.onboarding",
      kind: "services",
      label: "Onboarding",
      detail: `${endpoints} endpoints, ${toolsToOnboard} tool integration${toolsToOnboard === 1 ? "" : "s"}${onboarding > raw ? " (plan minimum)" : ""}`,
      monthly: 0,
      oneTime: round2(onboarding),
      costMonthly: 0,
      costOneTime: round2((endpoints > 0 ? endpoints * costOf("onb.endpoint") : 0) + (toolsToOnboard > 0 ? toolsToOnboard * costOf("onb.tool") : 0)),
    });
  }
  const annualService = (key: string, count: number, label: string, detail: string, item: string) => {
    if (count <= 0) return;
    lines.push({ key, kind: "services", label, detail, monthly: round2((count * need(item)) / 12), oneTime: 0, costMonthly: round2((count * costOf(item)) / 12), costOneTime: 0 });
  };
  annualService("services.ir", cfg.services.irExtraHours, "Extra incident-response hours", `${cfg.services.irExtraHours} h/year on top of the plan's ${plan?.irRetainerHours ?? 0} h`, "ps.ir.hour");
  annualService("services.pentest", cfg.services.pentests, "Penetration testing", `${cfg.services.pentests} per year`, "ps.pentest");
  annualService("services.training", cfg.services.trainingSessions, "Security awareness workshops", `${cfg.services.trainingSessions} per year`, "ps.training");

  // Premium support on the service subscription.
  const serviceMonthly = lines.filter((l) => l.kind === "service").reduce((s, l) => s + l.monthly, 0);
  if (cfg.services.premiumSupport) {
    const pct = need("svc.support.premium");
    lines.push({ key: "service.support", kind: "service", label: "Premium support", detail: `${pct}% of the managed service`, monthly: round2(serviceMonthly * (pct / 100)), oneTime: 0, costMonthly: 0, costOneTime: 0 });
  }

  // --- totals
  const monthlyGross = round2(lines.reduce((s, l) => s + l.monthly, 0));
  const planLine = lines.find((l) => l.key === "service.plan")?.monthly ?? 0;
  const tiers = [...ctx.volumeTiers].sort((a, b) => b.minEndpoints - a.minEndpoints);
  const volumeDiscountPct = tiers.find((t) => endpoints >= t.minEndpoints)?.discountPct ?? 0;
  const volumeDiscount = round2(planLine * (volumeDiscountPct / 100));
  const termDiscountPct = cfg.commercial.term === "annual" ? need("terms.annual") : cfg.commercial.term === "3year" ? need("terms.3year") : 0;
  // Term discounts apply to your service, not resold licences.
  const discountable = lines.filter((l) => l.kind !== "license").reduce((s, l) => s + l.monthly, 0) - volumeDiscount;
  const termDiscount = round2(discountable * (termDiscountPct / 100));
  const extraDiscount = round2((monthlyGross - volumeDiscount - termDiscount) * (cfg.commercial.extraDiscountPct / 100));
  const monthlyNet = round2(monthlyGross - volumeDiscount - termDiscount - extraDiscount);

  const oneTime = round2(lines.reduce((s, l) => s + l.oneTime, 0));
  const amcBase = lines.filter((l) => l.key === "ai.local").reduce((s, l) => s + l.oneTime, 0);
  const amcAnnual = amcBase > 0 ? round2(amcBase * (need("terms.amc") / 100)) : 0;
  const annualRecurring = round2(monthlyNet * 12);
  const year1Pre = annualRecurring + oneTime;
  const tax = round2(year1Pre * (cfg.commercial.taxPct / 100));
  const year1Total = round2(year1Pre + tax);
  const threeYearTotal = round2((annualRecurring * 3 + oneTime + amcAnnual * 2) * (1 + cfg.commercial.taxPct / 100));

  const costMonthly = round2(lines.reduce((s, l) => s + l.costMonthly, 0));
  const costYear1 = round2(costMonthly * 12 + lines.reduce((s, l) => s + l.costOneTime, 0));
  const revenueYear1 = annualRecurring + oneTime;
  const grossMarginPct = revenueYear1 > 0 && !costIncomplete ? round2(((revenueYear1 - costYear1) / revenueYear1) * 100) : null;

  // --- protection coverage of the chosen stack
  const coverage = CONTROLS.map((c) => {
    const by = selectedTools.filter((t) => t.controls.includes(c.key)).map(toolLabel);
    return { control: c.key, covered: by.length > 0, by, essential: c.essential };
  });
  const gaps = coverage.filter((c) => c.essential && !c.covered).map((c) => c.control);

  const known = cfg.commercial.currency === "USD" || ctx.currencies.some((c) => c.code === cfg.commercial.currency);
  if (!known) missing.push({ key: "currency", label: `Currency ${cfg.commercial.currency} isn't set up`, fix: "currency" });

  return {
    plan: plan ? { key: plan.key, name: plan.name, tagline: plan.tagline, coverage: plan.coverage, ackMinutes: plan.ackMinutes, irRetainerHours: plan.irRetainerHours } : null,
    lines,
    endpoints,
    monthlyGross,
    volumeDiscount,
    volumeDiscountPct,
    termDiscount,
    termDiscountPct,
    extraDiscount,
    monthlyNet,
    annualRecurring,
    oneTime,
    amcAnnual,
    amcMonthly: round2(amcAnnual / 12),
    tax,
    year1Total,
    threeYearTotal,
    perEndpointMonthly: endpoints ? round2(monthlyNet / endpoints) : 0,
    perUserMonthly: cfg.profile.users ? round2(monthlyNet / cfg.profile.users) : 0,
    costMonthly,
    costYear1,
    grossMarginPct,
    costIncomplete,
    coverage,
    gaps,
    missing,
    aiUsage,
    currency: known ? cfg.commercial.currency : "USD",
    fxRate: known ? cfg.commercial.fxRate : 1,
  };
}

export function comparePlans(cfg: QuoteConfig, ctx: PricingContext) {
  return ctx.plans.map((plan) => ({ plan, result: calculateQuote({ ...cfg, plan: plan.key }, ctx) }));
}

export function formatMoney(usd: number, currency: string, fxRate: number, opts: { decimals?: number } = {}) {
  const value = usd * fxRate;
  const decimals = opts.decimals ?? (Math.abs(value) >= 1000 ? 0 : 2);
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency, minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(value);
  } catch {
    return `${currency} ${value.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}`;
  }
}
