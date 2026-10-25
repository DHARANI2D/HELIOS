import { cache } from "react";

import { getSetting, platformEnvironment } from "@/lib/settings";
import { loadPricingContext } from "@/lib/pricing/service";
import type { PricingContext } from "@/lib/pricing/calculator";
import { publicContext } from "@/lib/pricing/public";
import { CATEGORIES, toolLabel } from "@/lib/integrations/catalog";
import { detectionCapabilities } from "@/lib/mitre/coverage";
import { TACTICS, getTechnique } from "@/lib/mitre/catalog";
import { DETECTORS } from "@/lib/siem/engine";
import { db } from "@/lib/db";
import type { PlatformFacts } from "@/lib/assets/designer";

// The public website's data: the MSSP's own settings, its prices and the
// platform's real capabilities. Nothing here is per-client.

export const siteSettings = cache(() => getSetting("site.public"));
export const companyProfile = cache(() => getSetting("company.profile"));

export async function publicPricingContext(): Promise<PricingContext> {
  return publicContext(await loadPricingContext());
}

// What the platform itself brings to a design: live detector, ATT&CK and
// playbook counts.
export const platformFacts = cache(async (): Promise<PlatformFacts> => {
  const [disabled, playbooks] = await Promise.all([getSetting("detection.disabledDetectors"), db.playbook.count({ where: { enabled: true } })]);
  const techniques = new Set(detectionCapabilities(disabled).map((c) => c.techniqueId));
  return {
    detectors: DETECTORS.filter((d) => !disabled.includes(d.name)).length,
    techniques: techniques.size,
    tactics: new Set([...techniques].map((t) => getTechnique(t)?.tactic).filter(Boolean)).size,
    playbooks,
  };
});

export async function loadHomeData() {
  const [company, site, environment, disabled, ctx] = await Promise.all([
    companyProfile(),
    siteSettings(),
    platformEnvironment(),
    getSetting("detection.disabledDetectors"),
    loadPricingContext(),
  ]);
  const techniques = new Set(detectionCapabilities(disabled).map((c) => c.techniqueId));
  const tactics = new Set([...techniques].map((t) => getTechnique(t)?.tactic).filter(Boolean));
  const categories = CATEGORIES.map((c) => ({
    key: c.key,
    label: c.label,
    description: c.description,
    tools: ctx.tools.filter((t) => t.category === c.key).map((t) => ({ key: t.key, label: toolLabel(t), alerts: !!t.ingest, actions: t.actions.length, offline: t.offlineCapable })),
  })).filter((c) => c.tools.length);
  return {
    company,
    site,
    environment,
    brand: company.name.trim() || "HELIOS",
    plans: ctx.plans.map((p) => ({ key: p.key, name: p.name, tagline: p.tagline, coverage: p.coverage, pricePerEndpoint: p.pricePerEndpoint, ackMinutes: p.ackMinutes, irRetainerHours: p.irRetainerHours, features: p.features })),
    categories,
    stats: {
      tools: ctx.tools.length,
      vendors: new Set(ctx.tools.map((t) => t.vendor)).size,
      withResponse: ctx.tools.filter((t) => t.actions.length).length,
      offline: ctx.tools.filter((t) => t.offlineCapable).length,
      techniques: techniques.size,
      tactics: tactics.size,
      totalTactics: TACTICS.length,
    },
  };
}
