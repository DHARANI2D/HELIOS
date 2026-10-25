import { getCategory, toolLabel, type CategoryKey, type ToolDefinition } from "@/lib/integrations/catalog";
import { PLATFORM_CAPABILITIES, PLATFORM_LABEL, capabilityName, type Capability } from "@/lib/assets/capabilities";
import { assetClass, assetPriorities, presentClasses, wantedCapabilities, type AssetClass, type ClassPriority } from "@/lib/assets/surface";
import { surfaceCoverage } from "@/lib/assets/coverage";
import { calculateQuote, formatMoney, normalizeConfig, toolMonthlyPrice, type PricingContext, type QuoteConfig, type QuoteResult } from "@/lib/pricing/calculator";
import { mixMobile, platformFit, type PlatformFit } from "@/lib/pricing/endpoint-mix";
import { applyChanges, capabilityWeigher, quoteDelta, stackTool, type QuoteDelta } from "@/lib/pricing/upgrades";

// The stack advisor's rules: for a client's attack surface (devices by OS,
// cloud, network, identities, IoT/OT, applications), the kind of
// organization it is and its current tools, which catalog tool each layer
// should have for a goal, and why. It reasons only from catalog facts
// (capabilities, supported platforms, alert and response integration,
// price for this client), weighted by the priority of the asset groups each
// capability protects, so every suggestion can be traced. The AI advisor
// (advisor-agent.ts) chooses among these candidates and adds judgment the
// catalog doesn't hold. Pure.

export type AdvisorGoal = "balanced" | "budget" | "protection";

export const ADVISOR_GOALS: Record<AdvisorGoal, { label: string; description: string }> = {
  balanced: {
    label: "Best value",
    description: "Everything each asset group requires, plus the recommended extras for P1 groups, with the lowest-priced tool that is nearly as strong as the best.",
  },
  budget: {
    label: "Lowest cost",
    description: "Only what the P1 asset groups require (devices, critical servers, identities, email), at the lowest price.",
  },
  protection: {
    label: "Strongest protection",
    description: "Every required and recommended capability for every asset group, with the most capable tool in each layer.",
  },
};

// Broader layers are decided first: an EDR that includes antivirus makes a
// separate antivirus unnecessary, and identity before email so MFA counts once.
const ORDER: CategoryKey[] = ["edr", "epp", "mdm", "mtd", "vuln", "identity", "pam", "email", "network", "netmgmt", "ndr", "cloud", "ot", "webapp", "code", "backup", "dlp", "siem", "awareness"];

// Layers whose own tools stay when the managed service covers them: HELIOS
// takes their alerts alongside its own detection.
const KEEP_OWN: CategoryKey[] = ["siem"];

export interface AdviceCandidate {
  key: string;
  label: string;
  value: number;
  adds: Capability[]; // wanted capabilities not yet in the stack
  essentials: number; // of those, required by a P1 asset group
  fit: PlatformFit | null;
  monthly: number | null;
  alerts: boolean;
  actions: number;
  offlineCapable: boolean;
  deployment: ToolDefinition["deployment"];
  priceUnit: ToolDefinition["price"]["unit"];
}

export type AdviceChange = "keep" | "add" | "switch" | "drop" | "skip";

export interface AdvicePick {
  category: CategoryKey;
  label: string;
  current: string; // the stack's choice now
  choice: string; // tool key, "byo" or "none"
  change: AdviceChange;
  tool: ToolDefinition | null;
  reasons: string[];
  monthly: number | null; // the choice for this client; 0 for the client's own or none
  priceDelta: number | null; // vs the current choice, tool level
  fit: PlatformFit | null;
  candidates: AdviceCandidate[]; // ranked best first
}

export interface Advice {
  goal: AdvisorGoal;
  picks: AdvicePick[];
  changes: Record<string, string>;
  config: QuoteConfig;
  before: QuoteResult;
  after: QuoteResult;
  delta: QuoteDelta;
  notes: string[];
}

const names = (cs: Capability[]) => {
  const n = cs.map(capabilityName);
  return n.length <= 1 ? n.join("") : `${n.slice(0, -1).join(", ")} and ${n[n.length - 1]}`;
};

interface Scoring {
  cfg: QuoteConfig;
  wanted: Set<Capability>;
  covered: Set<Capability>;
  weight: (c: Capability) => number;
  p1Required: Set<Capability>;
}

function scoreTool(tool: ToolDefinition, s: Scoring, serviceLayer: boolean, needed: boolean): AdviceCandidate {
  const { cfg } = s;
  const fit = platformFit(tool, cfg.profile.mix);
  const reach = fit?.ratio ?? 1;
  const adds = tool.controls.filter((c) => s.wanted.has(c) && !s.covered.has(c));
  const integration = (tool.ingest ? 1 : 0) + (tool.actions.length ? 1 : 0);
  const core = serviceLayer ? (needed ? 2 : 0) : adds.reduce((sum, c) => sum + Math.max(s.weight(c), 0.5), 0);
  // Alerts and response actions only count for a tool worth having.
  const value = core > 0 ? (core + integration * 0.5) * reach : 0;
  return {
    key: tool.key,
    label: toolLabel(tool),
    value: Math.round(value * 100) / 100,
    adds,
    essentials: adds.filter((c) => s.p1Required.has(c)).length,
    fit,
    monthly: toolMonthlyPrice(tool, cfg).monthly,
    alerts: !!tool.ingest,
    actions: tool.actions.length,
    offlineCapable: tool.offlineCapable,
    deployment: tool.deployment,
    priceUnit: tool.price.unit,
  };
}

const byPrice = (a: AdviceCandidate, b: AdviceCandidate) => (a.monthly ?? Number.POSITIVE_INFINITY) - (b.monthly ?? Number.POSITIVE_INFINITY) || b.value - a.value;
const byValue = (a: AdviceCandidate, b: AdviceCandidate) => b.value - a.value || byPrice(a, b);

function choose(candidates: AdviceCandidate[], goal: AdvisorGoal): AdviceCandidate | null {
  const useful = candidates.filter((c) => c.value > 0);
  if (!useful.length) return null;
  if (goal === "protection") return [...useful].sort(byValue)[0];
  // Machines the tool can't run on stay unprotected; prefer tools that reach
  // the whole estate when there are any.
  const full = useful.filter((c) => (c.fit?.ratio ?? 1) >= 0.999);
  const pool = full.length ? full : useful;
  const best = Math.max(...pool.map((c) => c.value));
  if (goal === "budget") {
    const most = Math.max(...pool.map((c) => c.essentials));
    return [...pool.filter((c) => c.essentials === most && (most > 0 || c.value >= best))].sort(byPrice)[0];
  }
  return [...pool.filter((c) => c.value >= best * 0.75)].sort(byPrice)[0];
}

// Who the reasons talk about: the client (Build & Price) or the visitor
// (the public estimator).
export type AdviceAudience = "staff" | "public";
const WORDS = {
  staff: { own: "the client's ", Own: "The client's ", them: "this client" },
  public: { own: "your ", Own: "Your ", them: "you" },
} as const;

const unsupportedText = (fit: PlatformFit) => fit.unsupported.map((u) => `${u.count.toLocaleString("en-US")} ${u.label}`).join(", ");

function fitReason(fit: PlatformFit | null, w: (typeof WORDS)[AdviceAudience]): string | null {
  if (!fit || fit.relevant === 0) return null;
  if (fit.agentless) return "Nothing to install on endpoints";
  if (!fit.unsupported.length) return `Runs on all ${fit.relevant.toLocaleString("en-US")} of ${w.own}devices it needs to cover`;
  return `Doesn't run on ${unsupportedText(fit)}`;
}

function integrationReason(c: AdviceCandidate): string | null {
  if (c.alerts && c.actions) return `Sends alerts to the SOC and supports ${c.actions} response action${c.actions === 1 ? "" : "s"}`;
  if (c.alerts) return "Sends alerts to the SOC";
  if (c.actions) return `Supports ${c.actions} response action${c.actions === 1 ? "" : "s"}`;
  return null;
}

// The asset groups a set of capabilities protects for this client, P1 first.
function protects(caps: Capability[], present: AssetClass[], priorities: Record<AssetClass, ClassPriority>) {
  const groups = present
    .filter((k) => caps.some((c) => assetClass(k).required.includes(c) || assetClass(k).recommended.includes(c)))
    .sort((a, b) => priorities[a].priority.localeCompare(priorities[b].priority))
    .slice(0, 3)
    .map((k) => `${assetClass(k).label} (${priorities[k].priority})`);
  return groups.length ? `protects ${groups.join(", ")}` : "";
}

export function adviseStack(input: QuoteConfig, ctx: PricingContext, goal: AdvisorGoal, audience: AdviceAudience = "staff"): Advice {
  const cfg = normalizeConfig(input);
  const w = WORDS[audience];
  const money = (usd: number) => formatMoney(usd, cfg.commercial.currency, cfg.commercial.fxRate, { decimals: Math.abs(usd) >= 100 ? 0 : 2 });
  const present = presentClasses(cfg.profile);
  const priorities = assetPriorities(cfg.context);
  const scoring: Scoring = {
    cfg,
    wanted: wantedCapabilities(goal, present, priorities),
    // The managed service brings the central data platform and playbooks.
    covered: new Set<Capability>(PLATFORM_CAPABILITIES),
    weight: capabilityWeigher(cfg),
    p1Required: new Set(present.filter((k) => priorities[k].priority === "P1").flatMap((k) => assetClass(k).required)),
  };
  const covered = scoring.covered;
  const coveredBy = new Map<Capability, string>(PLATFORM_CAPABILITIES.map((c) => [c, PLATFORM_LABEL]));
  const picks: AdvicePick[] = [];
  const changes: Record<string, string> = {};
  const notes: string[] = [];

  for (const key of ORDER) {
    const category = getCategory(key);
    if (!category?.priced) continue;
    const tools = ctx.tools.filter((t) => t.category === key);
    const serviceLayer = !tools.some((t) => t.controls.length);
    const needed = serviceLayer && key === "awareness" && cfg.profile.users > 0 && goal === "protection";
    const current = cfg.tools[key] ?? "none";
    const { tool: currentTool, source } = stackTool(cfg, ctx, key);
    const currentMonthly = currentTool ? toolMonthlyPrice(currentTool, cfg).monthly : current === "none" ? 0 : null;
    const candidates = tools.map((t) => scoreTool(t, scoring, serviceLayer, needed)).sort(byValue);
    let chosen = choose(candidates, goal);
    const cur = currentTool ? candidates.find((c) => c.key === currentTool.key) : undefined;
    const reasons: string[] = [];

    // Switching tools costs the client a migration: keep what's there when
    // it is nearly as good, unless the budget goal finds real savings. A
    // licence the client owns is kept more readily than one we would
    // resell. The best pick may be the very tool already there.
    let keep = !!cur && !!chosen && cur.key === chosen.key;
    const keepBar = current === "byo" ? 0.75 : 0.9;
    if (cur && chosen && cur.key !== chosen.key && cur.value >= chosen.value * keepBar && (cur.fit?.ratio ?? 1) >= (chosen.fit?.ratio ?? 1) - 0.05) {
      const saves = goal === "budget" && chosen.monthly != null && cur.monthly != null && chosen.monthly < cur.monthly * 0.9;
      if (!saves) {
        chosen = cur;
        keep = true;
      }
    }
    // The client's own tool that nobody named can't be judged; leave it.
    if (current === "byo" && !currentTool) {
      picks.push({ category: key, label: category.label, current, choice: "byo", change: "keep", tool: null, reasons: [`${w.Own}own tool. Name it to compare it with the catalog.`], monthly: 0, priceDelta: 0, fit: null, candidates });
      continue;
    }
    // A client's own SIEM stays: HELIOS ingests its alerts.
    if (!chosen && cur && current === "byo" && KEEP_OWN.includes(key)) {
      chosen = cur;
      keep = true;
    }

    let choice = "none";
    let change: AdviceChange;
    let monthly: number | null = 0;
    let tool: ToolDefinition | null = null;
    let fit: PlatformFit | null = null;

    if (!chosen) {
      change = current === "none" ? "skip" : "drop";
      const already = tools.flatMap((t) => t.controls).filter((c, i, a) => a.indexOf(c) === i && covered.has(c));
      if (already.length) reasons.push(`Not needed: ${names(already)} already come${already.length === 1 ? "s" : ""} from ${[...new Set(already.map((c) => coveredBy.get(c)!))].join(" and ")}`);
      else if (!tools.length) reasons.push("No tool for this layer in the catalog yet");
      else reasons.push(goal === "protection" ? `No tool in this layer adds protection for ${w.them}` : `Not part of the "${ADVISOR_GOALS[goal].label}" goal`);
      if (change === "drop" && currentMonthly) reasons.push(`Saves ${money(currentMonthly)}/month`);
    } else {
      tool = tools.find((t) => t.key === chosen.key)!;
      fit = chosen.fit;
      monthly = chosen.monthly;
      const keepsOwn = keep && current === "byo";
      choice = keepsOwn ? "byo" : tool.key;
      change = keep ? "keep" : current === "none" ? "add" : "switch";
      if (keep) reasons.push(`Keeps ${keepsOwn ? w.own : ""}${chosen.label}: nothing else in the catalog is clearly better for ${w.them}`);
      const curFit = cur?.fit;
      if (!keep && currentTool && curFit?.unsupported.length && (fit?.supported ?? 0) > curFit.supported) {
        reasons.push(`${source === "existing" ? w.Own : ""}${toolLabel(currentTool)} doesn't run on ${unsupportedText(curFit)}`);
      }
      if (chosen.adds.length) {
        const who = protects(chosen.adds, present, priorities);
        reasons.push(`${keep ? "Provides" : "Adds"} ${names(chosen.adds)}${who ? `; ${who}` : ""}`);
      } else if (keep && KEEP_OWN.includes(key)) reasons.push("Its alerts flow into the managed service alongside its own detection");
      else if (serviceLayer) reasons.push(category.description);
      const f = fitReason(fit, w);
      if (f) reasons.push(f);
      const i = integrationReason(chosen);
      if (i) reasons.push(i);
      if (keepsOwn) monthly = 0;
      else if (monthly == null) reasons.push("Price on request");
      else if (monthly === 0) reasons.push(tool.price.source ? `No licence fee (${tool.price.source})` : "No licence fee");
      else reasons.push(`${money(monthly)}/month for ${w.them}`);
      if (!keepsOwn && tool.price.unit === "user" && cfg.profile.users === 0) reasons.push("Priced per user: enter the number of users");
      for (const c of tool.controls) {
        if (!covered.has(c)) {
          covered.add(c);
          coveredBy.set(c, chosen.label);
        }
      }
    }

    const priceDelta = change === "keep" ? 0 : monthly == null || currentMonthly == null ? null : Math.round((monthly - currentMonthly) * 100) / 100;
    if (priceDelta && change === "switch" && currentTool) {
      reasons.push(`${money(Math.abs(priceDelta))}/month ${priceDelta < 0 ? "less" : "more"} than ${source === "existing" ? w.own : ""}${toolLabel(currentTool)}${source === "existing" ? " at catalog price" : ""}`);
    }
    if (choice !== current) changes[key] = choice;
    picks.push({ category: key, label: category.label, current, choice, change, tool, reasons, monthly, priceDelta, fit, candidates });
  }

  const config = applyChanges(cfg, changes);
  const before = calculateQuote(cfg, ctx);
  const after = calculateQuote(config, ctx);

  if (!cfg.profile.mix) notes.push(`Enter the endpoints by operating system to check that every suggested tool runs on all of ${w.own}machines.`);
  else {
    if (cfg.profile.mix.other > 0) notes.push(`${cfg.profile.mix.other.toLocaleString("en-US")} endpoints of unknown OS weren't checked against platform support.`);
    const mobile = mixMobile(cfg.profile.mix);
    if (mobile > 0 && !picks.some((p) => p.category === "mdm" && p.choice !== "none")) notes.push(`${mobile.toLocaleString("en-US")} phones and tablets have no device management.`);
    for (const p of picks) {
      if (p.tool && p.fit?.unsupported.length) notes.push(`${p.label}: ${toolLabel(p.tool)} leaves ${p.fit.unsupported.map((u) => `${u.count} ${u.label}`).join(", ")} without it; no catalog tool reaches every device.`);
    }
  }
  const unguarded = picks.filter((p) => (p.category === "email" || p.category === "identity") && p.choice === "none").map((p) => p.category);
  if (cfg.profile.users > 0 && unguarded.length) notes.push(`No ${unguarded.join(" or ")} protection: most attacks on small organizations start with a phishing email or a stolen password.`);
  if (!present.some((k) => !["user", "mobile", "server", "identity", "email"].includes(k))) {
    notes.push(`Add ${audience === "public" ? "your" : "the client's"} cloud accounts, network devices, IoT/OT devices and internet-facing apps to cover the whole attack surface.`);
  }
  const surface = surfaceCoverage(config, ctx);
  const open = surface.gaps.filter((g) => g.priority !== "P3");
  if (open.length) {
    const byGroup = new Map<AssetClass, Capability[]>();
    for (const g of open) byGroup.set(g.asset, [...(byGroup.get(g.asset) ?? []), g.capability]);
    notes.push(`Still uncovered: ${[...byGroup].map(([k, caps]) => `${assetClass(k).label} (${priorities[k].priority}): ${names(caps)}`).join("; ")}.`);
  }
  const onRequest = picks.filter((p) => p.tool && p.monthly == null && p.choice !== "byo").map((p) => toolLabel(p.tool!));
  if (onRequest.length) notes.push(`Priced on request: ${onRequest.join(", ")}.`);

  return { goal, picks, changes, config, before, after, delta: quoteDelta(before, after), notes };
}
