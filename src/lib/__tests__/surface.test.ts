import { describe, expect, it } from "vitest";

import { CATALOG_TOOLS } from "../../../prisma/seed-data/tools";
import { toolFromRow } from "@/lib/integrations/catalog";
import { parsePlan } from "@/lib/plans";
import { calculateQuote, defaultQuoteConfig, quoteConfigSchema, toolMonthlyPrice, type PricingContext, type QuoteConfig } from "@/lib/pricing/calculator";
import { EMPTY_MIX } from "@/lib/pricing/endpoint-mix";
import { adviseStack } from "@/lib/pricing/advisor";
import { EMPTY_CONTEXT, EMPTY_ESTATE, industryFromText, type Estate, type OrgContext } from "@/lib/assets/estate";
import { assetPriorities, classCounts, describeClassCount, presentClasses, wantedCapabilities } from "@/lib/assets/surface";
import { surfaceCoverage } from "@/lib/assets/coverage";
import { CAPABILITIES, isDeviceControl } from "@/lib/assets/capabilities";
import { designSolution } from "@/lib/assets/designer";
import { endpointClass, parseAssetClass, parseAssetType } from "@/lib/assets/inventory";
import { parseInventoryCsv } from "@/lib/endpoints/service";

const tools = CATALOG_TOOLS.map((t) => toolFromRow({ ...t, customPrice: null, active: true }));
const plan = parsePlan({
  id: "p1", key: "managed", name: "Managed", tagline: null, coverage: "24x7", ackMinutes: {}, containMinutes: {}, irRetainerHours: 0,
  pricePerEndpoint: 10, costPerEndpoint: null, onboardingMinimum: 0, defaultAutonomyCap: "SUGGEST", features: {}, active: true, sortOrder: 0,
});
const ctx: PricingContext = { plans: [plan], tools, book: {}, volumeTiers: [], models: [], currencies: [], aiBaseline: null };

function config(estate: Partial<Estate>, context: Partial<OrgContext> = {}, extra: Partial<QuoteConfig["profile"]> = {}): QuoteConfig {
  const base = defaultQuoteConfig(ctx);
  return quoteConfigSchema.parse({
    ...base,
    plan: "managed",
    context: { ...EMPTY_CONTEXT, ...context },
    profile: { ...base.profile, users: 120, mix: { ...EMPTY_MIX, windows: 100, windowsServer: 10, ios: 30 }, estate: { ...EMPTY_ESTATE, ...estate }, ...extra },
  });
}

describe("attack surface", () => {
  it("keeps the twelve device controls separate from the wider capabilities", () => {
    expect(CAPABILITIES.filter((c) => c.device)).toHaveLength(12);
    expect(isDeviceControl("edr")).toBe(true);
    expect(isDeviceControl("cspm")).toBe(false);
  });

  it("puts devices, critical servers, identities and email first by default", () => {
    const p = assetPriorities(EMPTY_CONTEXT);
    expect([p.user, p.server, p.identity, p.email].map((x) => x.priority)).toEqual(["P1", "P1", "P1", "P1"]);
    expect([p.cloud, p.network, p.apps, p.mobile].map((x) => x.priority)).toEqual(["P2", "P2", "P2", "P2"]);
    expect(p.iot_ot.priority).toBe("P3");
  });

  it("moves priorities with the organization, and says why", () => {
    const hospital = assetPriorities({ ...EMPTY_CONTEXT, industry: "healthcare" });
    expect(hospital.iot_ot).toEqual({ priority: "P1", reasons: ["Medical devices affect patient safety"] });
    expect(assetPriorities({ ...EMPTY_CONTEXT, environment: "cloud" }).cloud.priority).toBe("P1");
    expect(assetPriorities({ ...EMPTY_CONTEXT, environment: "onprem" }).cloud.priority).toBe("P3");
    expect(assetPriorities({ ...EMPTY_CONTEXT, industry: "technology" }).apps.priority).toBe("P1");
  });

  it("counts what the client has in each group", () => {
    const cfg = config({ cloudAccounts: 2, cloudWorkloads: 30, otDevices: 12, developers: 4 });
    const profile = { ...cfg.profile, workstations: 100, servers: 10 };
    const counts = classCounts(profile);
    expect(counts).toMatchObject({ user: 100, server: 10, mobile: 30, cloud: 32, iot_ot: 12, apps: 4, network: 0 });
    expect(describeClassCount("cloud", profile)).toBe("2 cloud accounts, 30 workloads");
    expect(presentClasses(profile)).not.toContain("network");
  });

  it("asks each goal for more", () => {
    const present = ["user", "identity", "cloud"] as const;
    const p = assetPriorities(EMPTY_CONTEXT);
    const budget = wantedCapabilities("budget", [...present], p);
    const balanced = wantedCapabilities("balanced", [...present], p);
    const strongest = wantedCapabilities("protection", [...present], p);
    expect(budget.has("edr") && budget.has("itdr")).toBe(true);
    expect(budget.has("cspm")).toBe(false); // cloud is P2
    expect(balanced.has("cspm") && balanced.has("vuln_scan")).toBe(true);
    expect(balanced.has("dlp")).toBe(false);
    expect(strongest.has("dlp") && strongest.has("sspm")).toBe(true);
    // The managed service is the SIEM and the SOAR.
    expect(strongest.has("siem")).toBe(false);
  });
});

describe("pricing the whole estate", () => {
  it("prices monitoring per asset and asks for prices nobody has set", () => {
    const priced: PricingContext = { ...ctx, book: { "svc.cloud.workload": { price: 4, cost: null }, "svc.network": { price: 6, cost: null } } };
    const r = calculateQuote(config({ cloudWorkloads: 30, networkDevices: 5, otDevices: 8 }), priced);
    expect(r.lines.find((l) => l.key === "service.cloud.workloads")!.monthly).toBe(120);
    expect(r.lines.find((l) => l.key === "service.network")!.monthly).toBe(30);
    expect(r.missing.map((m) => m.key)).toContain("svc.ot");
  });

  it("licenses new tools by their own unit", () => {
    const cfg = config({ cloudWorkloads: 30, developers: 4, otDevices: 8, iotDevices: 2 });
    const unit = (key: string) => toolMonthlyPrice(tools.find((t) => t.key === key)!, cfg);
    expect(unit("github_secret_protection")).toMatchObject({ qty: 4, monthly: 76 });
    expect(unit("wiz").qty).toBe(30);
    expect(unit("nozomi_guardian").qty).toBe(10);
    // Mobile threat defense counts phones and tablets only.
    expect(unit("lookout_mes").qty).toBe(30);
  });
});

describe("coverage and advice across the estate", () => {
  it("credits the managed service with SIEM and response, and lists real gaps", () => {
    const cov = surfaceCoverage(config({ cloudWorkloads: 10, networkDevices: 4 }), ctx);
    const network = cov.classes.find((c) => c.info.key === "network")!;
    expect(network.required.find((r) => r.capability === "siem")!.by).toEqual(["Managed service (HELIOS)"]);
    expect(network.gaps).toEqual(["net_config"]);
    expect(cov.gaps.some((g) => g.asset === "cloud" && g.capability === "cspm")).toBe(true);
    // P1 groups are listed first.
    expect(cov.classes[0].priority).toBe("P1");
  });

  it("covers OT first for a hospital, and every group it has", () => {
    const cfg = config({ cloudAccounts: 2, cloudWorkloads: 20, networkDevices: 10, otDevices: 60, internetApps: 2, developers: 5 }, { industry: "healthcare" });
    const a = adviseStack(cfg, ctx, "balanced");
    const pick = (k: string) => a.picks.find((p) => p.category === k)!;
    expect(pick("ot").change).toBe("add");
    expect(pick("ot").reasons.join(" ")).toMatch(/IoT & operational technology \(P1\)/);
    expect(pick("cloud").change).toBe("add");
    expect(pick("netmgmt").change).toBe("add");
    expect(pick("webapp").change).toBe("add");
    expect(pick("code").change).toBe("add");
    const after = surfaceCoverage(a.config, ctx);
    expect(after.gaps).toEqual([]);
    expect(after.score).toBe(100);
  });

  it("never counts a SaaS backup as protecting servers", () => {
    const a = adviseStack(config({}), ctx, "budget");
    expect(a.picks.find((p) => p.category === "backup")!.choice).not.toBe("m365_backup");
  });

  it("keeps a client's own SIEM: the managed service takes its alerts", () => {
    const cfg = { ...config({}), tools: { siem: "byo" }, existing: { siem: "splunk_cloud" } };
    const siem = adviseStack(cfg, ctx, "budget").picks.find((p) => p.category === "siem")!;
    expect(siem.change).toBe("keep");
    expect(siem.choice).toBe("byo");
  });
});

describe("solution designer", () => {
  const facts = { detectors: 20, techniques: 65, tactics: 12, playbooks: 8 };

  it("designs every asset group in priority order, with telemetry, detection and response", () => {
    const cfg = config({ cloudWorkloads: 20, networkDevices: 10, otDevices: 40, developers: 3 }, { industry: "manufacturing", companyType: "mid", environment: "hybrid", maturity: "some", delivery: "complete" });
    const d = designSolution(cfg, ctx, "balanced", "staff", facts);
    expect(d.title).toBe("Complete cybersecurity solution for a mid-sized enterprise in manufacturing");
    expect(d.groups[0].priority).toBe("P1");
    const ot = d.groups.find((g) => g.info.key === "iot_ot")!;
    expect(ot.priority).toBe("P1");
    expect(ot.reasons).toEqual(["Production depends on OT"]);
    expect(ot.deploy.find((x) => x.capability === "ot_monitoring")!.status).toBe("suggested");
    expect(ot.info.telemetry.length).toBeGreaterThan(0);
    expect(d.architecture.map((a) => a.layer)).toEqual(["Endpoint & asset layer", "Telemetry, alerts, configuration and asset data", "Central security data platform", "Detection & correlation", "Response & remediation"]);
    expect(d.architecture[3].items[0]).toMatch(/65 techniques across 12 tactics/);
    expect(d.phases[0].items.some((i) => i.startsWith("IoT & operational technology"))).toBe(true);
    expect(d.guidance.some((g) => /never automatic/.test(g))).toBe(true);
    expect(d.coverageAfter).toBeGreaterThan(d.coverageBefore);
  });

  it("keeps an endpoint deployment to devices and lists the rest for later", () => {
    const cfg = config({ cloudWorkloads: 5 }, { delivery: "edr" });
    const d = designSolution(cfg, ctx, "budget", "public", facts);
    expect(d.groups.find((g) => g.info.key === "cloud")!.inScope).toBe(false);
    expect(d.groups.find((g) => g.info.key === "user")!.inScope).toBe(true);
    expect(d.phases.at(-1)!.items.some((i) => i.startsWith("Cloud & workloads"))).toBe(true);
  });
});

describe("inventory by asset group", () => {
  it("places hosts by OS unless told what they are", () => {
    expect(endpointClass({ os: "Windows Server 2022" })).toBe("server");
    expect(endpointClass({ os: "iOS 18" })).toBe("mobile");
    expect(endpointClass({ os: null })).toBe("user");
    expect(endpointClass({ os: "FortiOS 7.4", assetClass: "network" })).toBe("network");
  });

  it("reads classes and types from imports, by key or by label", () => {
    expect(parseAssetClass("IoT & operational technology")).toBe("iot_ot");
    expect(parseAssetClass("network")).toBe("network");
    expect(parseAssetClass(undefined, "firewall")).toBe("network");
    expect(parseAssetType("Medical device")).toEqual({ class: "iot_ot", type: "medical" });
    expect(parseAssetClass("nonsense")).toBeNull();
  });

  it("takes class and type columns from an inventory CSV", () => {
    const rows = parseInventoryCsv("hostname,os,class,type\nclinic-fw01,FortiOS 7.4,network,firewall\ninfusion-07,,,medical\nlaptop-22,Windows 11,,");
    expect(rows.map((r) => [r.hostname, r.assetClass, r.assetType])).toEqual([
      ["clinic-fw01", "network", "firewall"],
      ["infusion-07", undefined, "medical"],
      ["laptop-22", undefined, undefined],
    ]);
  });
});

describe("client industry", () => {
  it("reads a free-text industry", () => {
    expect(industryFromText("Healthcare (test)")).toBe("healthcare");
    expect(industryFromText("Metal fabrication")).toBe("manufacturing");
    expect(industryFromText("Regional bank")).toBe("finance");
    expect(industryFromText("Law firm")).toBe("general");
    expect(industryFromText(null)).toBe("general");
  });
});
