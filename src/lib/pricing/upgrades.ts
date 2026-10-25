import { CATEGORIES, getCategory, toolLabel, type ToolCategory, type ToolDefinition } from "@/lib/integrations/catalog";
import { CONTROLS, type ProtectionControl } from "@/lib/endpoints/controls";
import { calculateQuote, normalizeConfig, toolMonthlyPrice, type PricingContext, type QuoteConfig, type QuoteResult } from "@/lib/pricing/calculator";
import { platformFit, type PlatformFit } from "@/lib/pricing/endpoint-mix";

// Upgrade review: for each layer of an existing stack (a saved quote, a
// client's live integrations, or what a visitor says they run today), what
// every other catalog tool would add or take away, whether it runs on the
// client's machines, and what it costs in comparison. Pure; prices come from
// the same calculator as quotes.

const ESSENTIAL = new Set(CONTROLS.filter((c) => c.essential).map((c) => c.key));
export const controlWeight = (c: ProtectionControl) => (ESSENTIAL.has(c) ? 3 : 1);
const weigh = (cs: ProtectionControl[]) => cs.reduce((s, c) => s + controlWeight(c), 0);

export type OptionKind = "upgrade" | "cheaper" | "trade-off" | "equivalent" | "downgrade";
const KIND_ORDER: OptionKind[] = ["upgrade", "cheaper", "trade-off", "equivalent", "downgrade"];

export interface UpgradeOption {
  tool: ToolDefinition;
  kind: OptionKind;
  gains: ProtectionControl[]; // controls this tool has and the baseline tool doesn't
  newToStack: ProtectionControl[]; // of those, the ones no other layer provides
  loses: ProtectionControl[];
  lostFromStack: ProtectionControl[]; // of those, the ones no other layer provides
  fit: PlatformFit | null;
  fitGain: number; // endpoints newly supported; negative = left out
  alertsGain: -1 | 0 | 1; // alerts into HELIOS gained or lost
  actionsGain: number; // response actions HELIOS can drive
  monthly: number | null; // this tool for this client, per month; null = price on request
  priceDelta: number | null; // vs the baseline tool at the same pricing
  score: number; // protection gained, for ordering
}

export interface CategoryReview {
  category: ToolCategory;
  choice: string; // what the stack has now: tool key, "byo" or "none"
  // The tool compared against: the estimate's tool, or the client's own one.
  baseline: ToolDefinition | null;
  source: "estimate" | "existing" | "unknown-own" | "none";
  baselineMonthly: number | null;
  baselineFit: PlatformFit | null;
  options: UpgradeOption[];
}

export function stackTool(cfg: QuoteConfig, ctx: PricingContext, category: string): { tool: ToolDefinition | null; source: CategoryReview["source"] } {
  const choice = cfg.tools[category] ?? "none";
  if (choice === "none") return { tool: null, source: "none" };
  if (choice === "byo") {
    const own = ctx.tools.find((t) => t.key === cfg.existing[category] && t.category === category);
    return own ? { tool: own, source: "existing" } : { tool: null, source: "unknown-own" };
  }
  const tool = ctx.tools.find((t) => t.key === choice && t.category === category);
  return tool ? { tool, source: "estimate" } : { tool: null, source: "none" };
}

// Controls the rest of the stack provides, layer by layer.
export function stackControls(cfg: QuoteConfig, ctx: PricingContext, except?: string): Set<ProtectionControl> {
  const out = new Set<ProtectionControl>();
  for (const c of CATEGORIES.filter((x) => x.priced && x.key !== except)) {
    for (const k of stackTool(cfg, ctx, c.key).tool?.controls ?? []) out.add(k);
  }
  return out;
}

function classify(gains: ProtectionControl[], lost: ProtectionControl[], fitGain: number, alertsGain: number, actionsGain: number, priceDelta: number | null): OptionKind {
  const better = gains.length > 0 || fitGain > 0 || alertsGain > 0 || actionsGain > 0;
  const worse = lost.length > 0 || fitGain < 0 || alertsGain < 0;
  if (better && !worse) return "upgrade";
  if (better && worse) return "trade-off";
  if (worse) return "downgrade";
  return priceDelta != null && priceDelta < 0 ? "cheaper" : "equivalent";
}

export function compareTool(tool: ToolDefinition, baseline: ToolDefinition | null, others: Set<ProtectionControl>, cfg: QuoteConfig): UpgradeOption {
  const base = baseline?.controls ?? [];
  const gains = tool.controls.filter((c) => !base.includes(c));
  const loses = base.filter((c) => !tool.controls.includes(c));
  const newToStack = gains.filter((c) => !others.has(c));
  const lostFromStack = loses.filter((c) => !others.has(c));
  const fit = platformFit(tool, cfg.profile.mix);
  const baseFit = baseline ? platformFit(baseline, cfg.profile.mix) : null;
  const fitGain = fit ? fit.supported - (baseline ? (baseFit?.supported ?? fit.relevant) : 0) : 0;
  const alertsGain = ((tool.ingest ? 1 : 0) - (baseline?.ingest ? 1 : 0)) as -1 | 0 | 1;
  const actionsGain = tool.actions.length - (baseline?.actions.length ?? 0);
  const monthly = toolMonthlyPrice(tool, cfg).monthly;
  const baseMonthly = baseline ? toolMonthlyPrice(baseline, cfg).monthly : 0;
  const priceDelta = monthly == null || baseMonthly == null ? null : Math.round((monthly - baseMonthly) * 100) / 100;
  // Protection gained: new controls weigh by importance and by how much of
  // the estate the tool reaches; alerts and actions make the SOC faster.
  const reach = fit?.ratio ?? 1;
  const baseReach = baseFit?.ratio ?? 1;
  const score =
    weigh(newToStack) * reach -
    weigh(lostFromStack) * baseReach +
    weigh(tool.controls.filter((c) => base.includes(c) && !others.has(c))) * (reach - baseReach) +
    alertsGain +
    Math.sign(actionsGain);
  return {
    tool,
    kind: baseline ? classify(gains, lostFromStack, fitGain, alertsGain, actionsGain, priceDelta) : "upgrade",
    gains,
    newToStack,
    loses,
    lostFromStack,
    fit,
    fitGain,
    alertsGain,
    actionsGain,
    monthly,
    priceDelta,
    score: Math.round(score * 100) / 100,
  };
}

export function reviewUpgrades(input: QuoteConfig, ctx: PricingContext): CategoryReview[] {
  const cfg = normalizeConfig(input);
  return CATEGORIES.filter((c) => c.priced).map((category) => {
    const { tool: baseline, source } = stackTool(cfg, ctx, category.key);
    const others = stackControls(cfg, ctx, category.key);
    const options = ctx.tools
      .filter((t) => t.category === category.key && t.key !== baseline?.key)
      .map((t) => compareTool(t, baseline, others, cfg))
      .sort(
        (a, b) =>
          KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) ||
          b.score - a.score ||
          (a.priceDelta ?? Number.POSITIVE_INFINITY) - (b.priceDelta ?? Number.POSITIVE_INFINITY),
      );
    return {
      category,
      choice: cfg.tools[category.key] ?? "none",
      baseline,
      source,
      baselineMonthly: baseline ? toolMonthlyPrice(baseline, cfg).monthly : null,
      baselineFit: baseline ? platformFit(baseline, cfg.profile.mix) : null,
      options,
    };
  });
}

// Puts the chosen tools into the stack (category → tool key, "byo" or
// "none"). Moving off the client's own tool keeps it on record as what they
// ran before.
export function applyChanges(input: QuoteConfig, changes: Record<string, string>): QuoteConfig {
  const cfg = normalizeConfig(input);
  const tools = { ...cfg.tools };
  for (const [category, choice] of Object.entries(changes)) {
    if (getCategory(category)?.priced) tools[category] = choice;
  }
  return { ...cfg, tools };
}

export interface QuoteDelta {
  monthly: number;
  oneTime: number;
  year1: number;
  threeYear: number;
  gapsClosed: ProtectionControl[];
  gapsOpened: ProtectionControl[];
  // Prices the new stack needs that aren't set (sold by quote).
  missing: string[];
}

const r2 = (n: number) => Math.round(n * 100) / 100;

export function quoteDelta(before: QuoteResult, after: QuoteResult): QuoteDelta {
  const had = new Set(before.missing.map((m) => m.key));
  return {
    monthly: r2(after.monthlyNet - before.monthlyNet),
    oneTime: r2(after.oneTime - before.oneTime),
    year1: r2(after.year1Total - before.year1Total),
    threeYear: r2(after.threeYearTotal - before.threeYearTotal),
    gapsClosed: before.gaps.filter((g) => !after.gaps.includes(g)),
    gapsOpened: after.gaps.filter((g) => !before.gaps.includes(g)),
    missing: after.missing.filter((m) => !had.has(m.key)).map((m) => m.label),
  };
}

// What applying a set of changes does to the whole quote: licences, the
// onboarding of new integrations, discounts, tax.
export function priceChanges(input: QuoteConfig, ctx: PricingContext, changes: Record<string, string>) {
  const before = calculateQuote(input, ctx);
  const config = applyChanges(input, changes);
  const after = calculateQuote(config, ctx);
  return { config, before, after, delta: quoteDelta(before, after) };
}

export const controlShort = (c: ProtectionControl) => CONTROLS.find((x) => x.key === c)?.short ?? c;
export const controlName = (c: ProtectionControl) => CONTROLS.find((x) => x.key === c)?.label ?? c;
export function choiceLabel(ctx: Pick<PricingContext, "tools">, choice: string, own?: string, audience: "staff" | "public" = "staff") {
  const whose = audience === "public" ? "Your" : "Client's";
  if (choice === "none") return "Not included";
  if (choice === "byo") return own ? `${whose} ${own}` : `${whose} own tool`;
  const tool = ctx.tools.find((t) => t.key === choice);
  return tool ? toolLabel(tool) : choice;
}
