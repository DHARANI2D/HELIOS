import { db } from "@/lib/db";
import { getCategory } from "@/lib/integrations/catalog";
import { defaultQuoteConfig, quoteConfigSchema, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { mixFromCounts, mixMobile, type EndpointMix } from "@/lib/pricing/endpoint-mix";

// A client's endpoints by OS from the inventory. When more endpoints are
// licensed than inventoried, the rest are counted as unknown OS.
export async function inventoryMix(tenantId: string, licensed = 0): Promise<EndpointMix | null> {
  const rows = await db.endpoint.groupBy({ by: ["os"], where: { tenantId }, _count: { _all: true } });
  return rows.length ? mixFromCounts(rows.map((r) => ({ os: r.os, count: r._count._all })), licensed) : null;
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

  const mix = await inventoryMix(tenantId, tenant.endpointsLicensed);
  const profile = mix
    ? { ...base.profile, mix, users: Math.max(base.profile.users, tenant.usersLicensed) }
    : { ...base.profile, workstations: Math.max(base.profile.workstations, tenant.endpointsLicensed - base.profile.servers), users: Math.max(base.profile.users, tenant.usersLicensed) };
  const config = quoteConfigSchema.parse({ ...base, clientName: tenant.name, tools, existing, profile });
  const mobile = mix ? mixMobile(mix) : 0;
  return {
    config,
    label: `${tenant.name}'s current setup${accepted ? ` (accepted quote ${accepted.reference})` : ""}${tenant.integrations.length ? `, ${tenant.integrations.length} onboarded tool${tenant.integrations.length === 1 ? "" : "s"}` : ""}${mobile ? `, ${mobile} mobile devices` : ""}`,
  };
}
