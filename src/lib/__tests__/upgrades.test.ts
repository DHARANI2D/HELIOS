import { describe, expect, it } from "vitest";

import { CATALOG_TOOLS } from "../../../prisma/seed-data/tools";
import { toolFromRow } from "@/lib/integrations/catalog";
import { parsePlan } from "@/lib/plans";
import { calculateQuote, defaultQuoteConfig, normalizeConfig, quoteConfigSchema, toolMonthlyPrice, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { EMPTY_MIX, classifyOs, mixFromInventory, platformFit, type EndpointMix } from "@/lib/pricing/endpoint-mix";
import { applyChanges, priceChanges, reviewUpgrades } from "@/lib/pricing/upgrades";
import { adviseStack } from "@/lib/pricing/advisor";
import { publicConfig, publicContext } from "@/lib/pricing/public";

// The real seeded catalog (vendor list prices, controls, platforms), so the
// engine is exercised on the data it runs on.
const tools = CATALOG_TOOLS.map((t) => toolFromRow({ ...t, customPrice: null, active: true }));
const plan = parsePlan({
  id: "p1", key: "managed", name: "Managed", tagline: null, coverage: "24x7",
  ackMinutes: { CRITICAL: 15 }, containMinutes: {}, irRetainerHours: 0,
  pricePerEndpoint: 10, costPerEndpoint: 6, onboardingMinimum: 0, defaultAutonomyCap: "SUGGEST", features: {}, active: true, sortOrder: 0,
});
const book = Object.fromEntries(
  Object.entries({ "svc.server": 8, "svc.identity": 1, "onb.endpoint": 15, "onb.tool": 300, "terms.annual": 5, "terms.3year": 10, "terms.resale": 0.8 }).map(([k, v]) => [k, { price: v, cost: null }]),
);
const ctx: PricingContext = { plans: [plan], tools, book, volumeTiers: [], models: [], currencies: [], aiBaseline: null };

const mix = (m: Partial<EndpointMix>): EndpointMix => ({ ...EMPTY_MIX, ...m });
function config(overrides: Omit<Partial<QuoteConfig>, "profile"> & { profile?: Partial<QuoteConfig["profile"]> } = {}): QuoteConfig {
  const base = defaultQuoteConfig(ctx);
  return quoteConfigSchema.parse({ ...base, ...overrides, plan: "managed", profile: { ...base.profile, users: 50, ...overrides.profile } });
}

describe("endpoint mix", () => {
  it("classifies inventory OS strings", () => {
    expect(classifyOs("Windows 11 Pro")).toBe("windows");
    expect(classifyOs("Windows Server 2022")).toBe("windowsServer");
    expect(classifyOs("macOS 15")).toBe("macos");
    expect(classifyOs("Ubuntu 24.04 LTS")).toBe("linuxServer");
    expect(classifyOs("Ubuntu 24.04 Desktop")).toBe("linux");
    expect(classifyOs("iPadOS 18")).toBe("ios");
    expect(classifyOs("Android 15")).toBe("android");
    expect(classifyOs(null)).toBe("other");
    expect(mixFromInventory(["Windows 11", "Windows 11", "Windows Server 2022", null])).toMatchObject({ windows: 2, windowsServer: 1, other: 1 });
  });

  it("takes workstation and server counts from the mix", () => {
    const c = normalizeConfig(config({ profile: { workstations: 999, servers: 999, mix: mix({ windows: 30, macos: 10, other: 2, linuxServer: 5, ios: 20 }) } }));
    expect(c.profile.workstations).toBe(42);
    expect(c.profile.servers).toBe(5);
    expect(calculateQuote(c, ctx).endpoints).toBe(47);
  });

  it("licenses phones and tablets for per-device MDM only", () => {
    const c = config({ profile: { mix: mix({ windows: 10, ios: 5 }) } });
    const perDeviceMdm = { ...tools.find((t) => t.key === "jamf_pro")!, price: { unit: "endpoint" as const, list: 4, custom: null, source: null } };
    expect(toolMonthlyPrice(perDeviceMdm, c).qty).toBe(15);
    expect(toolMonthlyPrice(tools.find((t) => t.key === "sentinelone_complete")!, c).qty).toBe(10);
  });

  it("finds the machines a tool can't run on", () => {
    const jamf = tools.find((t) => t.key === "jamf_pro")!;
    const fit = platformFit(jamf, mix({ windows: 30, macos: 10, ios: 5, linuxServer: 4 }))!;
    // MDM scope is computers and mobiles; servers aren't counted.
    expect(fit.relevant).toBe(45);
    expect(fit.supported).toBe(15);
    expect(fit.unsupported).toEqual([{ type: "windows", label: "Windows PCs", count: 30 }]);
    expect(platformFit(tools.find((t) => t.key === "opnsense")!, mix({ windows: 3 }))!.agentless).toBe(true);
    expect(platformFit(tools.find((t) => t.key === "entra_p1")!, mix({ windows: 3 }))).toBeNull();
  });
});

describe("existing tools", () => {
  it("names the client's own tool and counts it toward coverage", () => {
    const r = calculateQuote(config({ profile: { workstations: 20 }, tools: { edr: "byo" }, existing: { edr: "crowdstrike_falcon_enterprise" } }), ctx);
    expect(r.lines.find((l) => l.key === "license.edr")!.label).toContain("CrowdStrike Falcon Enterprise");
    expect(r.lines.find((l) => l.key === "license.edr")!.monthly).toBe(0);
    expect(r.coverage.find((c) => c.control === "edr")!.covered).toBe(true);
    expect(r.gaps).not.toContain("av");
  });

  it("keeps old saved configs valid", () => {
    const old = quoteConfigSchema.parse({ profile: { workstations: 5 }, ai: {}, services: {}, commercial: {} });
    expect(old.profile.mix).toBeNull();
    expect(old.existing).toEqual({});
  });
});

describe("upgrade review", () => {
  const estate = { mix: mix({ windows: 40, macos: 8, linuxServer: 6 }) };

  it("rates alternatives against the current tool, with price differences", () => {
    const reviews = reviewUpgrades(config({ profile: estate, tools: { edr: "crowdstrike_falcon_enterprise" } }), ctx);
    const edr = reviews.find((r) => r.category.key === "edr")!;
    expect(edr.baseline?.key).toBe("crowdstrike_falcon_enterprise");
    expect(edr.baselineMonthly).toBe(Math.round(54 * 15.42 * 100) / 100);
    const p2 = edr.options.find((o) => o.tool.key === "defender_endpoint_p2")!;
    expect(p2.kind).toBe("upgrade");
    expect(p2.gains.sort()).toEqual(["app_control", "vuln_scan"]);
    expect(p2.loses).toEqual([]);
    // 50 users × $5.20 vs 54 endpoints × $15.42
    expect(p2.priceDelta).toBeCloseTo(50 * 5.2 - 54 * 15.42, 2);
    const wazuh = edr.options.find((o) => o.tool.key === "wazuh")!;
    expect(wazuh.loses.sort()).toEqual(["av", "device_control", "host_firewall"]);
    expect(wazuh.kind).toBe("trade-off");
    // Upgrades are listed first.
    expect(edr.options[0].kind).toBe("upgrade");
  });

  it("treats a control another layer already provides as not lost", () => {
    const cfg = config({ profile: estate, tools: { edr: "crowdstrike_falcon_enterprise", epp: "crowdstrike_falcon_pro" } });
    const epp = reviewUpgrades(cfg, ctx).find((r) => r.category.key === "epp")!;
    const core = epp.options.find((o) => o.tool.key === "sentinelone_core")!;
    // Falcon Pro → Singularity Core drops device control and firewall, but
    // the EDR still has both.
    expect(core.loses.sort()).toEqual(["device_control", "host_firewall"]);
    expect(core.lostFromStack).toEqual([]);
    expect(core.kind).toBe("cheaper");
  });

  it("compares against the client's own tool when it's named", () => {
    const cfg = config({ profile: estate, tools: { mdm: "byo" }, existing: { mdm: "jamf_pro" } });
    const mdm = reviewUpgrades(cfg, ctx).find((r) => r.category.key === "mdm")!;
    expect(mdm.source).toBe("existing");
    const intune = mdm.options.find((o) => o.tool.key === "intune_p1")!;
    // Jamf doesn't run on the 40 Windows PCs; Intune does.
    expect(intune.fitGain).toBe(40);
    expect(intune.kind).toBe("upgrade");
  });

  it("prices a set of changes on the whole quote", () => {
    const cfg = config({ profile: estate, tools: { edr: "crowdstrike_falcon_enterprise" } });
    const { delta, after } = priceChanges(cfg, ctx, { mdm: "intune_p1" });
    expect(after.lines.some((l) => l.key === "license.intune_p1")).toBe(true);
    // Intune licence, plus onboarding one more tool.
    expect(delta.monthly).toBeCloseTo(50 * 8, 2);
    expect(delta.oneTime).toBe(300);
    expect(delta.gapsClosed.sort()).toEqual(["disk_encryption", "patching"]);
    expect(applyChanges(cfg, { nonsense: "x" }).tools).toEqual(cfg.tools);
  });
});

describe("stack advisor", () => {
  const estate = { mix: mix({ windows: 40, macos: 8, linuxServer: 6 }), logGbPerDay: 2 };

  it("closes every essential gap and skips layers others already cover", () => {
    const a = adviseStack(config({ profile: estate }), ctx, "balanced");
    expect(a.after.gaps).toEqual([]);
    const pick = (k: string) => a.picks.find((p) => p.category === k)!;
    expect(pick("edr").change).toBe("add");
    // The chosen EDR includes antivirus and a host firewall.
    expect(pick("epp").choice).toBe("none");
    expect(pick("epp").reasons[0]).toMatch(/^Not needed/);
    expect(pick("mdm").choice).toBe("intune_p1");
    expect(pick("siem").choice).toBe("helios_siem");
    expect(a.delta.monthly).toBeGreaterThan(0);
  });

  it("never suggests a tool that leaves machines out when one reaches them all", () => {
    const a = adviseStack(config({ profile: { mix: mix({ windows: 30, macos: 5, ios: 10 }) } }), ctx, "protection");
    const mdm = a.picks.find((p) => p.category === "mdm")!;
    expect(mdm.choice).toBe("intune_p1");
    expect(mdm.fit?.unsupported).toEqual([]);
  });

  it("drops a redundant paid layer on the lowest-cost goal and says what it saves", () => {
    const cfg = config({ profile: estate, tools: { edr: "crowdstrike_falcon_enterprise", epp: "crowdstrike_falcon_pro" } });
    const a = adviseStack(cfg, ctx, "budget");
    const epp = a.picks.find((p) => p.category === "epp")!;
    expect(epp.change).toBe("drop");
    expect(epp.reasons.join(" ")).toMatch(/Saves \$450/);
    expect(a.delta.monthly).toBeLessThan(0);
  });

  it("keeps the client's own tool when nothing is clearly better", () => {
    const cfg = config({ profile: estate, tools: { edr: "byo" }, existing: { edr: "sentinelone_complete" } });
    const edr = adviseStack(cfg, ctx, "balanced").picks.find((p) => p.category === "edr")!;
    expect(edr.change).toBe("keep");
    expect(edr.choice).toBe("byo");
    expect(edr.monthly).toBe(0);
    // Lowest cost does switch when the saving is real, priced like for like.
    const cheap = adviseStack(cfg, ctx, "budget").picks.find((p) => p.category === "edr")!;
    expect(cheap.change).toBe("switch");
    expect(cheap.choice).toBe("defender_business");
    expect(cheap.reasons.at(-1)).toMatch(/less than the client's SentinelOne Singularity Complete at catalog price/);
  });

  it("speaks to a website visitor as you, and says why their tool falls short", () => {
    const cfg = config({ profile: { mix: mix({ windows: 40, macos: 8 }) }, tools: { mdm: "byo" }, existing: { mdm: "jamf_pro" } });
    const mdm = adviseStack(cfg, ctx, "balanced", "public").picks.find((p) => p.category === "mdm")!;
    expect(mdm.change).toBe("switch");
    expect(mdm.reasons).toContain("Your Jamf Pro doesn't run on 40 Windows PCs");
    expect(mdm.reasons.join(" ")).toMatch(/of your devices/);
    expect(mdm.reasons.join(" ")).not.toMatch(/client/);
  });

  it("doesn't switch the client to the very tool they already own", () => {
    const cfg = config({ profile: estate, tools: { email: "byo" }, existing: { email: "defender_o365_p1" } });
    const email = adviseStack(cfg, ctx, "balanced").picks.find((p) => p.category === "email")!;
    expect(email.change).toBe("keep");
    expect(email.choice).toBe("byo");
  });

  it("asks for the endpoint mix when it's missing", () => {
    const a = adviseStack(config({ profile: { workstations: 10 } }), ctx, "balanced");
    expect(a.notes[0]).toMatch(/operating system/);
  });
});

describe("public estimator", () => {
  const withCosts: PricingContext = { ...ctx, book: { ...ctx.book, "onb.tool": { price: 300, cost: 150 } }, aiBaseline: { days: 90, cases: 120, endpoints: 300, casesPerEndpointMonth: 0.13, runs: 80, runsPerCase: 1.2, inputTokensPerRun: 9000, outputTokensPerRun: 900 } };

  it("never hands visitors costs, margins or client counts", () => {
    const pub = publicContext(withCosts);
    expect(pub.plans.every((p) => p.costPerEndpoint === null)).toBe(true);
    expect(Object.values(pub.book).every((v) => v.cost === null)).toBe(true);
    expect(pub.book["terms.resale"]).toBeUndefined();
    expect(pub.book["onb.tool"].price).toBe(300);
    expect(pub.aiBaseline).toMatchObject({ cases: 0, endpoints: 0, runs: 0, casesPerEndpointMonth: 0.13 });
  });

  it("resets the terms that are the team's to give, whatever the request says", () => {
    const crafted = config({ commercial: { term: "annual", currency: "USD", fxRate: 0.01, extraDiscountPct: 50, taxPct: 0 }, ai: { mode: "cloud", model: "made-up", hardware: "server", alertsPerMonth: 1, inputTokensPerRun: 1, outputTokensPerRun: 1 } });
    const safe = publicConfig(crafted, { ...ctx, currencies: [{ code: "EUR", symbol: "€", rate: 0.9 }], models: [{ model: "claude-opus-5-5", provider: "Anthropic", inputPer: 5, outputPer: 25 }] });
    expect(safe.commercial).toMatchObject({ term: "annual", currency: "USD", fxRate: 1, extraDiscountPct: 0, taxPct: 0 });
    expect(safe.ai).toMatchObject({ model: "claude-opus-5-5", alertsPerMonth: null, inputTokensPerRun: null, outputTokensPerRun: null });
    const eur = publicConfig({ ...crafted, commercial: { ...crafted.commercial, currency: "EUR" } }, { ...ctx, currencies: [{ code: "EUR", symbol: "€", rate: 0.9 }] });
    expect(eur.commercial).toMatchObject({ currency: "EUR", fxRate: 0.9 });
  });
});
