// What the MSSP's own price book holds: managed-service fees, onboarding,
// professional services, AI options and commercial terms. These are your
// rates, so none has a default — each starts unset, the calculator reports
// any it needs, and a quote can't be saved until they're filled in
// (Build & Price → Price book). Values live in the price_items table.

export type ItemUnit = "endpoint" | "server" | "user" | "account" | "workload" | "device" | "app" | "hour" | "engagement" | "session" | "month" | "one-time" | "percent" | "ratio";

export type PriceGroup = "Managed service" | "Onboarding" | "Professional services" | "AI" | "Commercial terms";

export interface PriceItemDef {
  key: string;
  group: PriceGroup;
  label: string;
  unit: ItemUnit;
  note?: string;
  // Whether a cost (for margin) makes sense for this item.
  hasCost: boolean;
}

export const PRICE_GROUPS: PriceGroup[] = ["Managed service", "Onboarding", "Professional services", "AI", "Commercial terms"];

export const PRICE_ITEMS: PriceItemDef[] = [
  { key: "svc.server", group: "Managed service", label: "Server monitoring surcharge", unit: "server", note: "Per server per month, on top of the plan; 0 if you don't charge one", hasCost: true },
  { key: "svc.identity", group: "Managed service", label: "Identity & email monitoring", unit: "user", note: "Per user per month; 0 if it's part of the plan", hasCost: true },
  { key: "svc.cloud.account", group: "Managed service", label: "Cloud account monitoring", unit: "account", note: "Per AWS account, Azure subscription or Google Cloud project per month", hasCost: true },
  { key: "svc.cloud.workload", group: "Managed service", label: "Cloud workload monitoring", unit: "workload", note: "Per VM, Kubernetes node or container workload per month", hasCost: true },
  { key: "svc.saas", group: "Managed service", label: "SaaS platform monitoring", unit: "app", note: "Per SaaS platform (Microsoft 365, Google Workspace, Salesforce…) per month", hasCost: true },
  { key: "svc.network", group: "Managed service", label: "Network & security device monitoring", unit: "device", note: "Per firewall, VPN gateway, switch or access point per month", hasCost: true },
  { key: "svc.iot", group: "Managed service", label: "IoT device monitoring", unit: "device", note: "Per camera, printer or smart device per month", hasCost: true },
  { key: "svc.ot", group: "Managed service", label: "OT / medical device monitoring", unit: "device", note: "Per PLC, HMI, medical or building-management device per month", hasCost: true },
  { key: "svc.app", group: "Managed service", label: "Internet-facing application monitoring", unit: "app", note: "Per website, portal or API per month", hasCost: true },
  { key: "svc.compliance", group: "Managed service", label: "Compliance evidence packs", unit: "month", note: "Add-on for plans that don't include it", hasCost: true },
  { key: "svc.dedicated", group: "Managed service", label: "Named lead analyst", unit: "month", note: "Add-on for plans that don't include it", hasCost: true },
  { key: "svc.support.premium", group: "Managed service", label: "Premium support", unit: "percent", note: "Share of the managed-service fee", hasCost: false },

  { key: "onb.endpoint", group: "Onboarding", label: "Endpoint onboarding", unit: "endpoint", note: "One-time per endpoint", hasCost: true },
  { key: "onb.tool", group: "Onboarding", label: "Tool integration", unit: "one-time", note: "One-time per onboarded tool", hasCost: true },

  { key: "ps.ir.hour", group: "Professional services", label: "Incident response hour (beyond the plan's retainer)", unit: "hour", hasCost: true },
  { key: "ps.pentest", group: "Professional services", label: "Penetration test", unit: "engagement", hasCost: true },
  { key: "ps.training", group: "Professional services", label: "Security awareness workshop", unit: "session", hasCost: true },

  { key: "ai.cloud.platform", group: "AI", label: "AI first response (cloud) platform fee", unit: "endpoint", note: "Per endpoint per month, on top of model usage", hasCost: true },
  { key: "ai.cloud.markup", group: "AI", label: "Markup on model usage", unit: "percent", note: "0 to pass model cost through at cost", hasCost: false },
  { key: "ai.local.workstation", group: "AI", label: "Local AI · GPU workstation", unit: "one-time", hasCost: true },
  { key: "ai.local.server", group: "AI", label: "Local AI · GPU server", unit: "one-time", hasCost: true },
  { key: "ai.local.cluster", group: "AI", label: "Local AI · inference cluster", unit: "one-time", hasCost: true },
  { key: "ai.local.hosting", group: "AI", label: "Local AI hosting, power & monitoring", unit: "month", hasCost: true },
  { key: "ai.local.setup", group: "AI", label: "Local AI setup & model tuning", unit: "one-time", hasCost: true },

  { key: "terms.annual", group: "Commercial terms", label: "Annual prepay discount", unit: "percent", note: "0 for none", hasCost: false },
  { key: "terms.3year", group: "Commercial terms", label: "3-year term discount", unit: "percent", note: "0 for none", hasCost: false },
  { key: "terms.amc", group: "Commercial terms", label: "Annual maintenance (AMC) on local AI hardware & setup", unit: "percent", note: "Charged from year 2", hasCost: false },
  { key: "terms.resale", group: "Commercial terms", label: "Tool resale: your cost as a share of the tool price", unit: "ratio", note: "0.8 = you buy at 80% of the price you resell at", hasCost: false },
];

export const PRICE_ITEM_INDEX = new Map(PRICE_ITEMS.map((i) => [i.key, i]));

export const ITEM_UNIT_LABEL: Record<ItemUnit, string> = {
  endpoint: "per endpoint",
  server: "per server",
  user: "per user",
  account: "per account",
  workload: "per workload",
  device: "per device",
  app: "per app",
  hour: "per hour",
  engagement: "per engagement",
  session: "per session",
  month: "per month",
  "one-time": "one-time",
  percent: "%",
  ratio: "ratio",
};

export type PriceBook = Record<string, { price: number | null; cost: number | null }>;
