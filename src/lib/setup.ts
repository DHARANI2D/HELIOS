import { db } from "@/lib/db";
import { CATEGORIES } from "@/lib/integrations/catalog";
import { PRICE_ITEMS } from "@/lib/pricing/items";
import { envClaudeAvailable } from "@/lib/ai/resolve";

// What a new install still needs before it can run a real service — all of
// it is your own data, so nothing is pre-filled. Shown to admins on the
// overview until every step is done.

export interface SetupStep {
  key: string;
  label: string;
  detail: string;
  done: boolean;
  href: string;
}

export async function setupChecklist(): Promise<SetupStep[]> {
  const priced = CATEGORIES.filter((c) => c.priced).map((c) => c.key);
  const [plans, priceSet, unpricedTools, providers, tenants, tenantsWithoutPlan, integrations, staff, feeds] = await Promise.all([
    db.servicePlan.count({ where: { active: true, pricePerEndpoint: { not: null } } }),
    db.priceItem.count({ where: { price: { not: null } } }),
    db.catalogTool.count({ where: { active: true, category: { in: priced }, listPrice: null, customPrice: null } }),
    db.aiProvider.count({ where: { enabled: true } }),
    db.tenant.count(),
    db.tenant.count({ where: { planId: null, status: { not: "SUSPENDED" } } }),
    db.integration.count({ where: { enabled: true } }),
    db.user.count({ where: { tenantId: null, active: true, role: { not: "ADMIN" } } }),
    db.threatFeed.count({ where: { enabled: true, lastImportedAt: { not: null } } }),
  ]);
  const ai = providers > 0 || envClaudeAvailable();
  return [
    { key: "plans", label: "Define your service plans", detail: plans ? `${plans} plan${plans === 1 ? "" : "s"} with a price` : "SLA targets, price per endpoint and what's included", done: plans > 0, href: "/pricing#setup" },
    { key: "prices", label: "Fill in your price book", detail: `${priceSet} of ${PRICE_ITEMS.length} rates set`, done: priceSet === PRICE_ITEMS.length, href: "/pricing#setup" },
    { key: "tools", label: "Price the quote-only tools you resell", detail: unpricedTools ? `${unpricedTools} offered tool${unpricedTools === 1 ? " has" : "s have"} no price (switch off the ones you don't sell)` : "Every offered tool has a price", done: unpricedTools === 0, href: "/pricing#setup" },
    { key: "ai", label: "Connect an AI provider", detail: ai ? "AI agents run on a language model" : "Until then, agents use the built-in deterministic engine", done: ai, href: "/ai" },
    { key: "team", label: "Invite your analysts", detail: staff ? `${staff} SOC account${staff === 1 ? "" : "s"}` : "One account per person, with the role they work in", done: staff > 0, href: "/team" },
    { key: "clients", label: "Add your first client", detail: tenants ? (tenantsWithoutPlan ? `${tenantsWithoutPlan} client${tenantsWithoutPlan === 1 ? " has" : "s have"} no plan, so no SLA` : `${tenants} client${tenants === 1 ? "" : "s"}`) : "Each client gets a plan, licences and AI consent", done: tenants > 0 && tenantsWithoutPlan === 0, href: "/tenants" },
    { key: "tools-onboarded", label: "Onboard a client's security tools", detail: integrations ? `${integrations} connected` : "EDR, identity and email alerts start flowing into cases", done: integrations > 0, href: "/integrations" },
    { key: "feeds", label: "Turn on threat feeds", detail: feeds ? `${feeds} feed${feeds === 1 ? "" : "s"} imported` : "Public blocklists the detectors match against", done: feeds > 0, href: "/threat-intel" },
  ];
}
