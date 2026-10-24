import type { PlanKey } from "@/lib/plans";

// The MSSP's own price book: managed-service fees, onboarding, professional
// services, AI options and commercial terms. Every figure is a default the
// admin overrides in Build & Price → Price book (PriceOverride rows), keyed
// by `key`. Third-party tool prices come from the integration catalog under
// `tool.<key>`.

export type ItemUnit = "endpoint" | "server" | "user" | "hour" | "engagement" | "session" | "month" | "one-time" | "percent" | "ratio";

export interface PriceItem {
  key: string;
  group: "Managed service" | "Onboarding" | "Professional services" | "AI" | "Commercial terms";
  label: string;
  unit: ItemUnit;
  price: number; // sell price, USD
  cost?: number; // your cost, USD (drives margin)
  note?: string;
}

export const PRICE_ITEMS: PriceItem[] = [
  { key: "svc.plan.essentials", group: "Managed service", label: "Essentials MDR", unit: "endpoint", price: 6, cost: 3, note: "Per endpoint per month" },
  { key: "svc.plan.professional", group: "Managed service", label: "Professional MDR", unit: "endpoint", price: 11, cost: 5.5, note: "Per endpoint per month" },
  { key: "svc.plan.enterprise", group: "Managed service", label: "Enterprise XDR", unit: "endpoint", price: 18, cost: 9, note: "Per endpoint per month" },
  { key: "svc.server", group: "Managed service", label: "Server monitoring surcharge", unit: "server", price: 12, cost: 6, note: "Servers carry more telemetry and higher stakes" },
  { key: "svc.identity", group: "Managed service", label: "Identity & email monitoring", unit: "user", price: 1.5, cost: 0.6 },
  { key: "svc.compliance", group: "Managed service", label: "Compliance evidence packs", unit: "month", price: 600, cost: 250 },
  { key: "svc.dedicated", group: "Managed service", label: "Named lead analyst", unit: "month", price: 3500, cost: 2200 },
  { key: "svc.support.premium", group: "Managed service", label: "Premium support (share of subscription)", unit: "percent", price: 8 },

  { key: "onb.endpoint", group: "Onboarding", label: "Endpoint onboarding", unit: "endpoint", price: 20, cost: 8, note: "One-time per endpoint" },
  { key: "onb.tool", group: "Onboarding", label: "Tool integration", unit: "one-time", price: 400, cost: 200, note: "Per onboarded tool" },
  { key: "onb.min.essentials", group: "Onboarding", label: "Minimum onboarding · Essentials", unit: "one-time", price: 1500 },
  { key: "onb.min.professional", group: "Onboarding", label: "Minimum onboarding · Professional", unit: "one-time", price: 3500 },
  { key: "onb.min.enterprise", group: "Onboarding", label: "Minimum onboarding · Enterprise", unit: "one-time", price: 9000 },

  { key: "ps.ir.hour", group: "Professional services", label: "Incident response (extra retainer hours)", unit: "hour", price: 250, cost: 120 },
  { key: "ps.pentest", group: "Professional services", label: "Penetration test", unit: "engagement", price: 6500, cost: 3500 },
  { key: "ps.training", group: "Professional services", label: "Security awareness workshop", unit: "session", price: 1200, cost: 500 },

  { key: "ai.cloud.platform", group: "AI", label: "AI first response (cloud)", unit: "endpoint", price: 0.5, cost: 0.1, note: "Platform fee per endpoint per month, plus model usage" },
  { key: "ai.cloud.markup", group: "AI", label: "Markup on model usage", unit: "percent", price: 30 },
  { key: "ai.local.workstation", group: "AI", label: "Local AI · GPU workstation (1× 24 GB)", unit: "one-time", price: 4500, cost: 3800 },
  { key: "ai.local.server", group: "AI", label: "Local AI · GPU server (2× 48 GB)", unit: "one-time", price: 12000, cost: 10000 },
  { key: "ai.local.cluster", group: "AI", label: "Local AI · inference cluster", unit: "one-time", price: 38000, cost: 32000 },
  { key: "ai.local.hosting", group: "AI", label: "Local AI hosting, power & monitoring", unit: "month", price: 180, cost: 120 },
  { key: "ai.local.setup", group: "AI", label: "Local AI setup & model tuning", unit: "one-time", price: 2500, cost: 1200 },

  { key: "terms.annual", group: "Commercial terms", label: "Annual prepay discount", unit: "percent", price: 8 },
  { key: "terms.3year", group: "Commercial terms", label: "3-year term discount", unit: "percent", price: 15 },
  { key: "terms.amc", group: "Commercial terms", label: "Annual maintenance (AMC) on hardware & setup", unit: "percent", price: 15 },
  { key: "terms.resale", group: "Commercial terms", label: "Tool resale: your cost as share of list", unit: "ratio", price: 0.8, note: "0.8 = you buy at 80% of list" },
];

// Volume discount on the per-endpoint service fee.
export const VOLUME_TIERS: Array<{ min: number; discountPct: number }> = [
  { min: 1000, discountPct: 20 },
  { min: 500, discountPct: 15 },
  { min: 250, discountPct: 10 },
  { min: 100, discountPct: 5 },
  { min: 0, discountPct: 0 },
];

export const PLAN_PRICE_KEY: Record<PlanKey, string> = {
  essentials: "svc.plan.essentials",
  professional: "svc.plan.professional",
  enterprise: "svc.plan.enterprise",
};

// Indicative FX against USD — edit to today's rate on the quote.
export const CURRENCIES: Record<string, { symbol: string; rate: number; locale: string }> = {
  USD: { symbol: "$", rate: 1, locale: "en-US" },
  EUR: { symbol: "€", rate: 0.92, locale: "de-DE" },
  GBP: { symbol: "£", rate: 0.79, locale: "en-GB" },
  INR: { symbol: "₹", rate: 83.5, locale: "en-IN" },
  AED: { symbol: "AED ", rate: 3.6725, locale: "en-AE" },
  SGD: { symbol: "S$", rate: 1.35, locale: "en-SG" },
  AUD: { symbol: "A$", rate: 1.52, locale: "en-AU" },
};

// Planning assumptions for cloud AI usage.
export const AI_USAGE = {
  alertsPerEndpointMonth: 2,
  alertsPerUserMonth: 0.4,
  triageInputTokens: 9000,
  triageOutputTokens: 1500,
  reportShare: 0.1, // share of alerts that get a client report
  reportInputTokens: 10000,
  reportOutputTokens: 2000,
};

export type PriceBook = Record<string, { price: number; cost?: number }>;

export function defaultPriceBook(): PriceBook {
  return Object.fromEntries(PRICE_ITEMS.map((i) => [i.key, { price: i.price, cost: i.cost }]));
}
