import { describe, expect, it } from "vitest";

import { can } from "@/lib/rbac";
import { parsePlan, slaDueAt, slaState, type ServicePlan } from "@/lib/plans";
import { calculateQuote, defaultQuoteConfig, formatMoney, quoteConfigSchema, type PricingContext } from "@/lib/pricing/calculator";
import { PRICE_ITEMS } from "@/lib/pricing/items";
import { toolFromRow, toolUnitPrice } from "@/lib/integrations/catalog";
import { decideResponse, type PolicyInput } from "@/lib/response/policy";
import { processAction } from "@/lib/governance/sidecar";
import { techniquesFor } from "@/lib/governance/runtime";
import { mapRecord, recordsFrom } from "@/lib/integrations/mappers";
import { samplePayloadFor } from "@/lib/__tests__/fixtures/vendor-payloads";

const plan: ServicePlan = parsePlan({
  id: "p1",
  key: "test-24x7",
  name: "Test 24x7",
  tagline: null,
  coverage: "24x7",
  ackMinutes: { CRITICAL: 30, HIGH: 120, INFO: -5, LOW: "x" },
  containMinutes: { CRITICAL: 120 },
  irRetainerHours: 10,
  pricePerEndpoint: 10,
  costPerEndpoint: 5,
  onboardingMinimum: 1000,
  defaultAutonomyCap: "AUTO_CONTAIN",
  features: { monitoring: "24×7", compliance: false, threatHunting: "" },
  active: true,
  sortOrder: 0,
});

const tool = toolFromRow({
  key: "edr_x", name: "EDR X", vendor: "Vendor", category: "edr", description: "test", controls: ["edr", "av"], actions: ["ISOLATE_HOST"],
  ingest: "generic", platforms: ["Windows"], deployment: "cloud", offlineCapable: false, priceUnit: "endpoint", listPrice: 4, priceSource: "test", customPrice: null, active: true,
});
const quoteOnly = toolFromRow({ ...tool, key: "id_y", name: "ID Y", category: "identity", controls: [], actions: [], ingest: null, platforms: [], priceUnit: "user", listPrice: null, priceSource: "Sold by quote", customPrice: null, active: true, deployment: "cloud", offlineCapable: false, description: "test", vendor: "Vendor" });

function ctx(overrides: Partial<PricingContext> = {}): PricingContext {
  return {
    plans: [plan],
    tools: [tool, quoteOnly],
    book: Object.fromEntries(PRICE_ITEMS.map((i) => [i.key, { price: i.unit === "ratio" ? 0.8 : i.unit === "percent" ? 10 : 2, cost: i.hasCost ? 1 : null }])),
    volumeTiers: [{ minEndpoints: 100, discountPct: 10 }],
    models: [{ model: "claude-opus-5-5", provider: "Anthropic", inputPer: 4, outputPer: 20 }],
    currencies: [{ code: "EUR", symbol: "€", rate: 0.9 }],
    aiBaseline: null,
    ...overrides,
  };
}

describe("service plans and SLA", () => {
  it("parses only valid SLA minutes and non-empty features", () => {
    expect(plan.ackMinutes).toEqual({ CRITICAL: 30, HIGH: 120, MEDIUM: null, LOW: null, INFO: null });
    expect(plan.features).toEqual({ monitoring: "24×7", compliance: false });
  });

  it("gives no SLA without a plan", () => {
    const at = new Date("2026-10-24T08:00:00Z");
    expect(slaDueAt(at, "CRITICAL", null)).toBeNull();
    expect(slaDueAt(at, "CRITICAL", plan)?.toISOString()).toBe("2026-10-24T08:30:00.000Z");
    expect(slaDueAt(at, "MEDIUM", plan)).toBeNull();
  });

  it("tracks SLA state", () => {
    const createdAt = new Date("2026-10-24T08:00:00Z");
    const slaDue = new Date("2026-10-24T08:30:00Z");
    expect(slaState({ createdAt, slaDueAt: slaDue, acknowledgedAt: null }, new Date("2026-10-24T08:10:00Z"))).toBe("due");
    expect(slaState({ createdAt, slaDueAt: slaDue, acknowledgedAt: null }, new Date("2026-10-24T08:25:00Z"))).toBe("at_risk");
    expect(slaState({ createdAt, slaDueAt: slaDue, acknowledgedAt: null }, new Date("2026-10-24T08:31:00Z"))).toBe("breached");
    expect(slaState({ createdAt, slaDueAt: slaDue, acknowledgedAt: new Date("2026-10-24T08:20:00Z") }, new Date())).toBe("met");
  });
});

describe("Build & Price calculator", () => {
  const cfg = () => quoteConfigSchema.parse({ ...defaultQuoteConfig(ctx()), profile: { workstations: 90, servers: 10, users: 80, logGbPerDay: 0 }, tools: { edr: "edr_x" } });

  it("prices only from the context and reports nothing missing when complete", () => {
    const r = calculateQuote(cfg(), ctx());
    expect(r.missing).toEqual([]);
    expect(r.lines.find((l) => l.key === "service.plan")?.monthly).toBe(1000); // 100 × 10
    expect(r.lines.find((l) => l.key === "license.edr_x")).toMatchObject({ monthly: 400, basis: "list", costMonthly: 320 });
    expect(r.volumeDiscountPct).toBe(10);
    expect(r.plan?.name).toBe("Test 24x7");
  });

  it("reports every unset price instead of assuming one", () => {
    const r = calculateQuote({ ...cfg(), tools: { edr: "edr_x", identity: "id_y" }, ai: { ...cfg().ai, mode: "cloud" } }, ctx({ book: {} }));
    const keys = r.missing.map((m) => m.key);
    expect(keys).toEqual(expect.arrayContaining(["svc.server", "svc.identity", "onb.endpoint", "tool.id_y", "ai.alerts", "ai.tokens", "ai.cloud.platform"]));
    expect(r.grossMarginPct).toBeNull();
  });

  it("asks for a plan when none is defined", () => {
    const r = calculateQuote(cfg(), ctx({ plans: [] }));
    expect(r.missing[0]).toMatchObject({ key: "plan", fix: "plan" });
  });

  it("estimates cloud AI from measured history, and lets the user override it", () => {
    const base = { days: 90, cases: 300, endpoints: 100, casesPerEndpointMonth: 1, runs: 600, runsPerCase: 2, inputTokensPerRun: 10_000, outputTokensPerRun: 1000 };
    const c = { ...cfg(), ai: { ...cfg().ai, mode: "cloud" as const } };
    const r = calculateQuote(c, ctx({ aiBaseline: base }));
    expect(r.aiUsage).toMatchObject({ alertsPerMonth: 100, runsPerMonth: 200, source: "history" });
    expect(r.aiUsage?.modelCostMonthly).toBe(12); // 200 × (10k × $4 + 1k × $20) / 1M
    const o = calculateQuote({ ...c, ai: { ...c.ai, alertsPerMonth: 50 } }, ctx({ aiBaseline: base }));
    expect(o.aiUsage).toMatchObject({ alertsPerMonth: 50, source: "entered" });
  });

  it("uses your price over the vendor's and flags quote-only tools", () => {
    expect(toolUnitPrice(tool)).toBe(4);
    expect(toolUnitPrice({ ...tool, price: { ...tool.price, custom: 3 } })).toBe(3);
    expect(toolUnitPrice(quoteOnly)).toBeNull();
  });

  it("rejects unknown currencies and formats known ones", () => {
    expect(calculateQuote({ ...cfg(), commercial: { ...cfg().commercial, currency: "XYZ" } }, ctx()).missing.some((m) => m.fix === "currency")).toBe(true);
    expect(formatMoney(1234.5, "EUR", 0.9)).toBe("€1,111");
  });
});

describe("response policy", () => {
  const base: PolicyInput = { actionType: "ISOLATE_HOST", grounded: true, confidence: 0.95, killSwitch: false, autonomy: "AUTO_CONTAIN", allowedActions: ["ISOLATE_HOST", "BLOCK_IP"], minConfidence: 0.85, tenantCap: "AUTO_CONTAIN", endpointCriticality: "standard", autoActionsLastHour: 0, maxAutoActionsPerHour: 5 };

  it("executes only when every guardrail passes", () => {
    expect(decideResponse(base).status).toBe("EXECUTED");
    expect(decideResponse({ ...base, grounded: false }).status).toBe("BLOCKED");
    expect(decideResponse({ ...base, killSwitch: true }).status).toBe("SUGGESTED");
    expect(decideResponse({ ...base, tenantCap: "CONTAIN_WITH_APPROVAL" }).status).toBe("PENDING_APPROVAL");
    expect(decideResponse({ ...base, confidence: 0.6 }).status).toBe("PENDING_APPROVAL");
    expect(decideResponse({ ...base, endpointCriticality: "critical" }).status).toBe("PENDING_APPROVAL");
    expect(decideResponse({ ...base, autoActionsLastHour: 5 }).status).toBe("PENDING_APPROVAL");
    expect(decideResponse({ ...base, actionType: "DISABLE_USER", allowedActions: ["DISABLE_USER"] }).status).toBe("PENDING_APPROVAL");
  });
});

describe("governance gate", () => {
  it("maps blocked actions to ATT&CK techniques", () => {
    const dlp = processAction({ name: "SEND_EXTERNAL_REQUEST", payload_sample: { customer_emails: ["someone@customer.test"] }, confidence: 0.95 }, "production");
    expect(dlp).toMatchObject({ decision: "DENY", layer: "DLP" });
    expect(techniquesFor(dlp, "SEND_EXTERNAL_REQUEST")).toEqual(["T1567"]);
    const breach = processAction({ name: "ESCALATE_OWN_PRIVILEGE" }, "production");
    expect(breach.layer).toBe("CONSTITUTION");
    expect(techniquesFor(breach, "ESCALATE_OWN_PRIVILEGE")).toEqual(["T1078"]);
  });
});

describe("roles", () => {
  it("keeps clients and sales away from SOC tooling", () => {
    expect(can({ role: "CLIENT_VIEWER" }, "containment.approve")).toBe(false);
    expect(can({ role: "SALES" }, "cases.view")).toBe(false);
    expect(can({ role: "SALES" }, "pricing.view")).toBe(true);
    expect(can({ role: "INCIDENT_RESPONDER" }, "containment.approve")).toBe(true);
    expect(can({ role: "TRIAGE_ANALYST" }, "pricing.manage")).toBe(false);
  });
});

describe("vendor alert mappers", () => {
  it("maps each vendor's own payload shape to alerts", () => {
    const crowdstrike = recordsFrom(samplePayloadFor({ ingest: "crowdstrike", category: "edr" })).map((r) => mapRecord("crowdstrike", r, "endpoint"));
    expect(crowdstrike[0]).toMatchObject({ kind: "alert", alert: { severity: "CRITICAL", host: "FIN-LAPTOP-07" } });
    const defender = recordsFrom(samplePayloadFor({ ingest: "defender", category: "edr" })).map((r) => mapRecord("defender", r, "endpoint"));
    expect(defender[0].kind).toBe("alert");
    if (defender[0].kind === "alert") expect(defender[0].alert.techniques).toEqual(expect.arrayContaining(["T1059.001"]));
  });
});
