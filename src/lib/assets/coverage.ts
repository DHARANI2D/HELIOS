import { toolLabel } from "@/lib/integrations/catalog";
import { PLATFORM_CAPABILITIES, PLATFORM_LABEL, type Capability } from "@/lib/assets/capabilities";
import { ASSET_CLASSES, assetPriorities, classCounts, describeClassCount, type AssetClass, type AssetClassInfo, type Priority } from "@/lib/assets/surface";
import { normalizeConfig, stackTools, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";

// How well a stack covers the client's attack surface: for every asset
// group they have, which of its required and recommended capabilities some
// tool provides (licensed, the client's own, or the managed service
// itself), and which are gaps. Pure.

export interface CapabilityCover {
  capability: Capability;
  by: string[];
}

export interface ClassCoverage {
  info: AssetClassInfo;
  count: number;
  describe: string;
  priority: Priority;
  reasons: string[];
  required: CapabilityCover[];
  recommended: CapabilityCover[];
  gaps: Capability[]; // required and not covered
}

export interface SurfaceCoverage {
  classes: ClassCoverage[]; // the groups the client has, P1 first
  missing: AssetClass[]; // groups with nothing counted yet
  gaps: Array<{ asset: AssetClass; capability: Capability; priority: Priority }>;
  score: number; // share of required capabilities covered, weighted by priority (0-100)
}

export function surfaceCoverage(input: QuoteConfig, ctx: Pick<PricingContext, "tools" | "plans">): SurfaceCoverage {
  const cfg = normalizeConfig(input);
  const profile = { ...cfg.profile, estate: cfg.profile.estate };
  const counts = classCounts(profile);
  const priorities = assetPriorities(cfg.context);
  const providers = new Map<Capability, string[]>();
  const add = (cap: Capability, by: string) => providers.set(cap, [...(providers.get(cap) ?? []), by]);
  for (const { tool, own } of stackTools(cfg, ctx)) for (const cap of tool.controls) add(cap, own ? `${toolLabel(tool)} (client's)` : toolLabel(tool));
  if (ctx.plans.some((p) => p.key === cfg.plan)) PLATFORM_CAPABILITIES.forEach((cap) => add(cap, PLATFORM_LABEL));

  const cover = (caps: Capability[]) => caps.map((capability) => ({ capability, by: providers.get(capability) ?? [] }));
  const classes = ASSET_CLASSES.filter((c) => counts[c.key] > 0)
    .map((info) => {
      const required = cover(info.required);
      return {
        info,
        count: counts[info.key],
        describe: describeClassCount(info.key, profile),
        priority: priorities[info.key].priority,
        reasons: priorities[info.key].reasons,
        required,
        recommended: cover(info.recommended),
        gaps: required.filter((r) => !r.by.length).map((r) => r.capability),
      };
    })
    .sort((a, b) => a.priority.localeCompare(b.priority));

  const weight = { P1: 3, P2: 2, P3: 1 } as const;
  let earned = 0;
  let possible = 0;
  for (const c of classes) {
    possible += weight[c.priority] * c.required.length;
    earned += weight[c.priority] * c.required.filter((r) => r.by.length).length;
  }
  return {
    classes,
    missing: ASSET_CLASSES.filter((c) => counts[c.key] === 0).map((c) => c.key),
    gaps: classes.flatMap((c) => c.gaps.map((capability) => ({ asset: c.info.key, capability, priority: c.priority }))),
    score: possible ? Math.round((earned / possible) * 100) : 0,
  };
}

// The asset groups a quote covers beyond computers, servers and mailboxes,
// in words: "network & security devices (12 devices); iot & …".
export function extraGroupsText(input: QuoteConfig): string {
  const cfg = normalizeConfig(input);
  const counts = classCounts(cfg.profile);
  return ASSET_CLASSES.filter((c) => !["user", "server", "email"].includes(c.key) && counts[c.key] > 0)
    .map((c) => `${c.label.toLowerCase()} (${describeClassCount(c.key, cfg.profile)})`)
    .join("; ");
}
