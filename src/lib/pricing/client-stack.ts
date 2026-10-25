import { db } from "@/lib/db";
import { getCategory } from "@/lib/integrations/catalog";
import { defaultQuoteConfig, quoteConfigSchema, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { mixFromCounts, mixMobile, type EndpointMix } from "@/lib/pricing/endpoint-mix";
import { DEVICE_CLASSES, OT_TYPES, endpointClass } from "@/lib/assets/inventory";
import { industryFromText, type Estate } from "@/lib/assets/estate";

// A client's inventory as quote inputs: computers, servers and phones by OS
// (licensed endpoints beyond the inventory count as unknown OS), and the
// rest of the attack surface counted by asset group and type.
export async function inventoryProfile(tenantId: string, licensed = 0): Promise<{ mix: EndpointMix | null; estate: Partial<Estate> }> {
  const rows = await db.endpoint.groupBy({ by: ["os", "assetClass", "assetType"], where: { tenantId }, _count: { _all: true } });
  const devices: Array<{ os: string | null; count: number }> = [];
  const estate: Partial<Estate> = {};
  const bump = (k: keyof Estate, n: number) => (estate[k] = (estate[k] ?? 0) + n);
  for (const r of rows) {
    const n = r._count._all;
    const cls = endpointClass(r);
    if (DEVICE_CLASSES.includes(cls)) devices.push({ os: r.os, count: n });
    else if (cls === "network") bump("networkDevices", n);
    else if (cls === "iot_ot") bump(r.assetType && OT_TYPES.has(r.assetType) ? "otDevices" : "iotDevices", n);
    else if (cls === "cloud") bump(r.assetType === "cloud_account" ? "cloudAccounts" : r.assetType === "saas" ? "saasApps" : "cloudWorkloads", n);
    else if (cls === "apps" && r.assetType !== "repository" && r.assetType !== "ci_runner") bump("internetApps", n);
  }
  return { mix: devices.length ? mixFromCounts(devices, licensed) : null, estate };
}

// What a client has today, as a quote to review upgrades against: their
// accepted quote when there is one (it is the contract), otherwise their
// plan; sized from the endpoint inventory; and every tool they have
// onboarded recorded as theirs.
export async function clientStackConfig(tenantId: string, ctx: Pick<PricingContext, "plans" | "models" | "tools">): Promise<{ config: QuoteConfig; label: string } | null> {
  const tenant = await db.tenant.findUnique({
    where: { id: tenantId },
    include: {
      plan: { select: { key: true } },
      integrations: { where: { enabled: true }, select: { vendor: true, category: true } },
      quotes: { where: { status: "ACCEPTED" }, orderBy: { updatedAt: "desc" }, take: 1, select: { reference: true, config: true } },
    },
  });
  if (!tenant) return null;
  const accepted = tenant.quotes[0];
  const parsed = accepted ? quoteConfigSchema.safeParse(accepted.config) : null;
  const base: QuoteConfig = parsed?.success ? parsed.data : { ...defaultQuoteConfig(ctx), plan: tenant.plan?.key ?? defaultQuoteConfig(ctx).plan };

  const tools = { ...base.tools };
  const existing = { ...base.existing };
  for (const i of tenant.integrations) {
    if (!getCategory(i.category)?.priced || !ctx.tools.some((t) => t.key === i.vendor && t.category === i.category)) continue;
    const choice = tools[i.category] ?? "none";
    // A tool we already resell stays as it is; anything else is theirs.
    if (choice === "none" || choice === "byo") {
      tools[i.category] = "byo";
      existing[i.category] = i.vendor;
    }
  }

  const { mix, estate: counted } = await inventoryProfile(tenantId, tenant.endpointsLicensed);
  const estate = { ...base.profile.estate };
  for (const [k, v] of Object.entries(counted) as Array<[keyof Estate, number]>) estate[k] = Math.max(estate[k], v);
  const profile = mix
    ? { ...base.profile, mix, estate, users: Math.max(base.profile.users, tenant.usersLicensed) }
    : { ...base.profile, estate, workstations: Math.max(base.profile.workstations, tenant.endpointsLicensed - base.profile.servers), users: Math.max(base.profile.users, tenant.usersLicensed) };
  // The client's recorded industry sets priorities unless the quote says otherwise.
  const context = base.context.industry === "general" ? { ...base.context, industry: industryFromText(tenant.industry) } : base.context;
  const config = quoteConfigSchema.parse({ ...base, clientName: tenant.name, tools, existing, profile, context });
  const mobile = mix ? mixMobile(mix) : 0;
  return {
    config,
    label: `${tenant.name}'s current setup${accepted ? ` (accepted quote ${accepted.reference})` : ""}${tenant.integrations.length ? `, ${tenant.integrations.length} onboarded tool${tenant.integrations.length === 1 ? "" : "s"}` : ""}${mobile ? `, ${mobile} mobile devices` : ""}`,
  };
}
