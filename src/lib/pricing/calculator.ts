import { z } from "zod";

import { PLANS, PLAN_KEYS, type PlanKey } from "@/lib/plans";
import { CATEGORIES, getTool, type ToolDefinition } from "@/lib/integrations/catalog";
import { CONTROLS, type ProtectionControl } from "@/lib/endpoints/controls";
import { MODEL_PRICING } from "@/lib/ai/catalog";
import { AI_USAGE, CURRENCIES, PLAN_PRICE_KEY, VOLUME_TIERS, defaultPriceBook, type PriceBook } from "@/lib/pricing/catalog";

// Build & Price: turns a client profile + chosen stack into a priced quote.
// Pure and deterministic (no I/O), so the configurator recalculates live in
// the browser and the saved quote is re-derivable from its config.

export const quoteConfigSchema = z.object({
  clientName: z.string().max(120).default(""),
  profile: z.object({
    workstations: z.number().int().min(0).max(1_000_000).default(100),
    servers: z.number().int().min(0).max(100_000).default(10),
    users: z.number().int().min(0).max(1_000_000).default(100),
    logGbPerDay: z.number().min(0).max(100_000).default(5),
  }),
  plan: z.enum(PLAN_KEYS as [PlanKey, ...PlanKey[]]).default("professional"),
  // Per category: a tool key, "byo" (client already licenses one), or "none".
  tools: z.record(z.string(), z.string()).default({}),
  ai: z.object({
    mode: z.enum(["none", "cloud", "local"]).default("cloud"),
    model: z.string().default("claude-opus-5-5"),
    hardware: z.enum(["workstation", "server", "cluster"]).default("server"),
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
    term: z.enum(["monthly", "annual", "3year"]).default("annual"),
    currency: z.string().default("USD"),
    fxRate: z.number().positive().default(1),
    extraDiscountPct: z.number().min(0).max(50).default(0),
    taxPct: z.number().min(0).max(40).default(0),
  }),
});

export type QuoteConfig = z.infer<typeof quoteConfigSchema>;

export function defaultQuoteConfig(): QuoteConfig {
  return quoteConfigSchema.parse({
    profile: {},
    ai: {},
    services: {},
    commercial: {},
    tools: { edr: "defender_business", identity: "entra_p1", email: "defender_o365_p1", mdm: "intune_p1", siem: "helios_siem" },
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
  basis?: "list" | "estimate" | "included";
}

export interface QuoteResult {
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
  coverage: Array<{ control: ProtectionControl; covered: boolean; by: string[]; essential: boolean }>;
  gaps: ProtectionControl[];
  estimates: number; // lines priced on estimates
  aiUsage: { alertsPerMonth: number; tokensPerMonth: number; modelCostMonthly: number } | null;
  currency: string;
  fxRate: number;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

function priceOf(book: PriceBook, key: string, fallback = 0) {
  return book[key]?.price ?? fallback;
}
function costOf(book: PriceBook, key: string) {
  return book[key]?.cost ?? 0;
}

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

const GENERIC_VENDORS = new Set(["HELIOS", "In-house", "Generic", "Any provider", "Open source"]);

export function toolLabel(tool: ToolDefinition) {
  return GENERIC_VENDORS.has(tool.vendor) || tool.name.startsWith(tool.vendor) ? tool.name : `${tool.vendor} ${tool.name}`;
}

export function toolMonthlyPrice(tool: ToolDefinition, cfg: QuoteConfig, book: PriceBook = {}) {
  const unitPrice = book[`tool.${tool.key}`]?.price ?? tool.price.amount;
  const { qty, label } = toolUnits(tool, cfg);
  return { monthly: round2(unitPrice * qty), unitPrice, qty, label };
}

export function calculateQuote(input: QuoteConfig, overrides: PriceBook = {}): QuoteResult {
  const cfg = quoteConfigSchema.parse(input);
  const book: PriceBook = { ...defaultPriceBook(), ...overrides };
  const plan = PLANS[cfg.plan];
  const endpoints = cfg.profile.workstations + cfg.profile.servers;
  const lines: QuoteLine[] = [];

  // --- managed service
  const perEndpoint = priceOf(book, PLAN_PRICE_KEY[cfg.plan]);
  lines.push({
    key: "service.plan",
    kind: "service",
    label: `${plan.name} (${plan.coverage})`,
    detail: `${endpoints} endpoints × ${perEndpoint.toFixed(2)}`,
    monthly: round2(endpoints * perEndpoint),
    oneTime: 0,
    costMonthly: round2(endpoints * costOf(book, PLAN_PRICE_KEY[cfg.plan])),
    costOneTime: 0,
  });
  if (cfg.profile.servers > 0) {
    lines.push({
      key: "service.server",
      kind: "service",
      label: "Server monitoring",
      detail: `${cfg.profile.servers} servers × ${priceOf(book, "svc.server").toFixed(2)}`,
      monthly: round2(cfg.profile.servers * priceOf(book, "svc.server")),
      oneTime: 0,
      costMonthly: round2(cfg.profile.servers * costOf(book, "svc.server")),
      costOneTime: 0,
    });
  }
  if (cfg.profile.users > 0) {
    lines.push({
      key: "service.identity",
      kind: "service",
      label: "Identity & email monitoring",
      detail: `${cfg.profile.users} users × ${priceOf(book, "svc.identity").toFixed(2)}`,
      monthly: round2(cfg.profile.users * priceOf(book, "svc.identity")),
      oneTime: 0,
      costMonthly: round2(cfg.profile.users * costOf(book, "svc.identity")),
      costOneTime: 0,
    });
  }
  if (cfg.services.compliance && plan.features.compliance === false) {
    lines.push({ key: "service.compliance", kind: "service", label: "Compliance evidence packs", detail: "monthly", monthly: priceOf(book, "svc.compliance"), oneTime: 0, costMonthly: costOf(book, "svc.compliance"), costOneTime: 0 });
  }
  if (cfg.services.dedicatedAnalyst && plan.features.dedicatedAnalyst !== true) {
    lines.push({ key: "service.dedicated", kind: "service", label: "Named lead analyst", detail: "monthly", monthly: priceOf(book, "svc.dedicated"), oneTime: 0, costMonthly: costOf(book, "svc.dedicated"), costOneTime: 0 });
  }

  // --- tool licences (resold at list; you buy at the resale ratio)
  const resale = priceOf(book, "terms.resale", 0.8);
  const selectedTools: ToolDefinition[] = [];
  let toolsToOnboard = 0;
  for (const category of CATEGORIES) {
    const choice = cfg.tools[category.key];
    if (!choice || choice === "none") continue;
    toolsToOnboard++;
    if (choice === "byo") {
      lines.push({ key: `license.${category.key}`, kind: "license", label: `${category.label}: client's existing tool`, detail: "no licence resold", monthly: 0, oneTime: 0, costMonthly: 0, costOneTime: 0 });
      continue;
    }
    const tool = getTool(choice);
    if (!tool || tool.category !== category.key) continue;
    selectedTools.push(tool);
    const { monthly, unitPrice, label } = toolMonthlyPrice(tool, cfg, book);
    lines.push({
      key: `license.${tool.key}`,
      kind: "license",
      label: toolLabel(tool),
      detail: monthly ? `${label} × ${unitPrice.toFixed(2)}` : tool.price.note ?? "no licence fee",
      monthly,
      oneTime: 0,
      costMonthly: round2(monthly * resale),
      costOneTime: 0,
      basis: tool.price.basis,
    });
  }

  // --- AI
  let aiUsage: QuoteResult["aiUsage"] = null;
  if (cfg.ai.mode === "cloud") {
    const alerts = Math.round(endpoints * AI_USAGE.alertsPerEndpointMonth + cfg.profile.users * AI_USAGE.alertsPerUserMonth);
    const input = alerts * AI_USAGE.triageInputTokens + alerts * AI_USAGE.reportShare * AI_USAGE.reportInputTokens;
    const output = alerts * AI_USAGE.triageOutputTokens + alerts * AI_USAGE.reportShare * AI_USAGE.reportOutputTokens;
    const price = MODEL_PRICING[cfg.ai.model] ?? MODEL_PRICING["claude-opus-5-5"];
    const modelCost = (input * price.input + output * price.output) / 1_000_000;
    const markup = priceOf(book, "ai.cloud.markup") / 100;
    aiUsage = { alertsPerMonth: alerts, tokensPerMonth: Math.round(input + output), modelCostMonthly: round2(modelCost) };
    lines.push({
      key: "ai.cloud",
      kind: "ai",
      label: "AI first response · cloud",
      detail: `${endpoints} endpoints × ${priceOf(book, "ai.cloud.platform").toFixed(2)} + ~${alerts} AI triages/month on ${cfg.ai.model}`,
      monthly: round2(endpoints * priceOf(book, "ai.cloud.platform") + modelCost * (1 + markup)),
      oneTime: 0,
      costMonthly: round2(endpoints * costOf(book, "ai.cloud.platform") + modelCost),
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
      monthly: priceOf(book, "ai.local.hosting"),
      oneTime: round2(priceOf(book, hw) + priceOf(book, "ai.local.setup")),
      costMonthly: costOf(book, "ai.local.hosting"),
      costOneTime: round2(costOf(book, hw) + costOf(book, "ai.local.setup")),
    });
  }

  // --- onboarding & professional services (one-time / annual)
  const onboardingRaw = endpoints * priceOf(book, "onb.endpoint") + toolsToOnboard * priceOf(book, "onb.tool");
  const onboarding = Math.max(onboardingRaw, priceOf(book, `onb.min.${cfg.plan}`));
  lines.push({
    key: "onetime.onboarding",
    kind: "services",
    label: "Onboarding",
    detail: `${endpoints} endpoints, ${toolsToOnboard} tool integration${toolsToOnboard === 1 ? "" : "s"}${onboarding > onboardingRaw ? " (plan minimum)" : ""}`,
    monthly: 0,
    oneTime: round2(onboarding),
    costMonthly: 0,
    costOneTime: round2(endpoints * costOf(book, "onb.endpoint") + toolsToOnboard * costOf(book, "onb.tool")),
  });
  if (cfg.services.irExtraHours > 0) {
    lines.push({
      key: "services.ir",
      kind: "services",
      label: "Extra incident-response hours",
      detail: `${cfg.services.irExtraHours} h/year on top of the plan's ${plan.irRetainerHours} h`,
      monthly: round2((cfg.services.irExtraHours * priceOf(book, "ps.ir.hour")) / 12),
      oneTime: 0,
      costMonthly: round2((cfg.services.irExtraHours * costOf(book, "ps.ir.hour")) / 12),
      costOneTime: 0,
    });
  }
  if (cfg.services.pentests > 0) {
    lines.push({
      key: "services.pentest",
      kind: "services",
      label: "Penetration testing",
      detail: `${cfg.services.pentests} per year`,
      monthly: round2((cfg.services.pentests * priceOf(book, "ps.pentest")) / 12),
      oneTime: 0,
      costMonthly: round2((cfg.services.pentests * costOf(book, "ps.pentest")) / 12),
      costOneTime: 0,
    });
  }
  if (cfg.services.trainingSessions > 0) {
    lines.push({
      key: "services.training",
      kind: "services",
      label: "Security awareness workshops",
      detail: `${cfg.services.trainingSessions} per year`,
      monthly: round2((cfg.services.trainingSessions * priceOf(book, "ps.training")) / 12),
      oneTime: 0,
      costMonthly: round2((cfg.services.trainingSessions * costOf(book, "ps.training")) / 12),
      costOneTime: 0,
    });
  }

  // Premium support on the service subscription.
  const serviceMonthly = lines.filter((l) => l.kind === "service").reduce((s, l) => s + l.monthly, 0);
  if (cfg.services.premiumSupport) {
    lines.push({
      key: "service.support",
      kind: "service",
      label: "Premium support",
      detail: `${priceOf(book, "svc.support.premium")}% of the managed service`,
      monthly: round2(serviceMonthly * (priceOf(book, "svc.support.premium") / 100)),
      oneTime: 0,
      costMonthly: 0,
      costOneTime: 0,
    });
  }

  // --- totals
  const monthlyGross = round2(lines.reduce((s, l) => s + l.monthly, 0));
  const planLine = lines[0].monthly;
  const volumeDiscountPct = VOLUME_TIERS.find((t) => endpoints >= t.min)?.discountPct ?? 0;
  const volumeDiscount = round2(planLine * (volumeDiscountPct / 100));
  const termDiscountPct = cfg.commercial.term === "annual" ? priceOf(book, "terms.annual") : cfg.commercial.term === "3year" ? priceOf(book, "terms.3year") : 0;
  // Term discounts apply to your service, not resold licences.
  const discountable = lines.filter((l) => l.kind !== "license").reduce((s, l) => s + l.monthly, 0) - volumeDiscount;
  const termDiscount = round2(discountable * (termDiscountPct / 100));
  const extraDiscount = round2((monthlyGross - volumeDiscount - termDiscount) * (cfg.commercial.extraDiscountPct / 100));
  const monthlyNet = round2(monthlyGross - volumeDiscount - termDiscount - extraDiscount);

  const oneTime = round2(lines.reduce((s, l) => s + l.oneTime, 0));
  const amcBase = lines.filter((l) => l.key === "ai.local").reduce((s, l) => s + l.oneTime, 0);
  const amcAnnual = round2(amcBase * (priceOf(book, "terms.amc") / 100));
  const annualRecurring = round2(monthlyNet * 12);
  const year1Pre = annualRecurring + oneTime;
  const tax = round2(year1Pre * (cfg.commercial.taxPct / 100));
  const year1Total = round2(year1Pre + tax);
  const threeYearTotal = round2((annualRecurring * 3 + oneTime + amcAnnual * 2) * (1 + cfg.commercial.taxPct / 100));

  const costMonthly = round2(lines.reduce((s, l) => s + l.costMonthly, 0));
  const costYear1 = round2(costMonthly * 12 + lines.reduce((s, l) => s + l.costOneTime, 0));
  const revenueYear1 = annualRecurring + oneTime;
  const grossMarginPct = revenueYear1 > 0 ? round2(((revenueYear1 - costYear1) / revenueYear1) * 100) : null;

  // --- protection coverage of the chosen stack
  const coverage = CONTROLS.map((c) => {
    const by = selectedTools.filter((t) => t.controls.includes(c.key)).map(toolLabel);
    return { control: c.key, covered: by.length > 0, by, essential: c.essential };
  });
  const gaps = coverage.filter((c) => c.essential && !c.covered).map((c) => c.control);

  const currency = CURRENCIES[cfg.commercial.currency] ? cfg.commercial.currency : "USD";
  return {
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
    coverage,
    gaps,
    estimates: lines.filter((l) => l.basis === "estimate").length,
    aiUsage,
    currency,
    fxRate: cfg.commercial.fxRate,
  };
}

export function comparePlans(cfg: QuoteConfig, book: PriceBook = {}) {
  return PLAN_KEYS.map((plan) => ({ plan, result: calculateQuote({ ...cfg, plan }, book) }));
}

export function formatMoney(usd: number, currency: string, fxRate: number, opts: { decimals?: number } = {}) {
  const info = CURRENCIES[currency] ?? CURRENCIES.USD;
  const value = usd * fxRate;
  const decimals = opts.decimals ?? (Math.abs(value) >= 1000 ? 0 : 2);
  return `${info.symbol}${value.toLocaleString(info.locale, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}`;
}
