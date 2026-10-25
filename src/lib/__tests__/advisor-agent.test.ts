import { beforeEach, describe, expect, it, vi } from "vitest";

import type { LlmProvider } from "@/lib/ai/provider";

// The model is faked; what's under test is that its picks are held to the
// candidates the rules priced, and that failures fall back to the rules.
const state = vi.hoisted(() => ({ provider: null as LlmProvider | null, runs: [] as unknown[] }));
vi.mock("@/lib/ai/resolve", () => ({
  resolveAgent: async () => ({ profile: { key: "advisor", enabled: true, effort: "low", instructions: null }, provider: state.provider }),
}));
vi.mock("@/lib/db", () => ({ db: { aiRun: { create: async (args: { data: unknown }) => state.runs.push(args.data) } } }));

import { CATALOG_TOOLS } from "../../../prisma/seed-data/tools";
import { toolFromRow } from "@/lib/integrations/catalog";
import { parsePlan } from "@/lib/plans";
import { defaultQuoteConfig, quoteConfigSchema, type PricingContext } from "@/lib/pricing/calculator";
import { EMPTY_MIX } from "@/lib/pricing/endpoint-mix";
import { runAdvisorAgent } from "@/lib/pricing/advisor-agent";

const tools = CATALOG_TOOLS.map((t) => toolFromRow({ ...t, customPrice: null, active: true }));
const plan = parsePlan({ id: "p1", key: "managed", name: "Managed", tagline: null, coverage: "24x7", ackMinutes: {}, containMinutes: {}, irRetainerHours: 0, pricePerEndpoint: 10, costPerEndpoint: null, onboardingMinimum: 0, defaultAutonomyCap: "SUGGEST", features: {}, active: true, sortOrder: 0 });
const ctx: PricingContext = { plans: [plan], tools, book: { "onb.tool": { price: 300, cost: null }, "onb.endpoint": { price: 15, cost: null } }, volumeTiers: [], models: [], currencies: [], aiBaseline: null };
const cfg = quoteConfigSchema.parse({
  ...defaultQuoteConfig(ctx),
  plan: "managed",
  profile: { workstations: 0, servers: 0, users: 40, logGbPerDay: 0, mix: { ...EMPTY_MIX, windows: 35, macos: 5 } },
  tools: { edr: "sentinelone_complete", epp: "sentinelone_core" },
});

function fakeProvider(picks: Array<{ layer: string; choice: string; reason: string }>, opts: { fail?: boolean } = {}): LlmProvider {
  return {
    name: "Fake model",
    kind: "anthropic",
    model: "fake-1",
    isLocal: false,
    async structured() {
      if (opts.fail) throw new Error("overloaded");
      return { data: { summary: "Keep SentinelOne, drop the separate antivirus, add Intune.", picks } as never, model: "fake-1", usage: { inputTokens: 1200, outputTokens: 300 } };
    },
    async text() {
      throw new Error("unused");
    },
    async check() {
      return { ok: true, message: "" };
    },
  };
}

describe("AI stack advisor", () => {
  beforeEach(() => {
    state.provider = null;
    state.runs = [];
  });

  it("answers from the rules when no model is configured", async () => {
    const a = await runAdvisorAgent(cfg, ctx, "balanced", { audience: "public", trigger: "website" });
    expect(a.status).toBe("rules");
    expect(a.engine).toBe("built-in");
    expect(a.changes.mdm).toBe("intune_p1");
    expect(a.summary).toMatch(/Best value/);
    expect(state.runs).toHaveLength(0);
  });

  it("keeps the model's valid picks and replaces invented ones with the rules' pick", async () => {
    state.provider = fakeProvider([
      { layer: "edr", choice: "keep", reason: "SentinelOne already covers the estate." },
      { layer: "epp", choice: "none", reason: "The EDR includes antivirus." },
      { layer: "mdm", choice: "acme_mdm_ultra", reason: "Made up." },
      { layer: "identity", choice: "entra_p1", reason: "Conditional access for Microsoft 365." },
    ]);
    const a = await runAdvisorAgent(cfg, ctx, "balanced", { audience: "staff", trigger: "manual", requestedById: "u1" });
    expect(a.status).toBe("succeeded");
    expect(a.model).toBe("fake-1");
    expect(a.changes.edr).toBeUndefined(); // kept
    expect(a.changes.epp).toBe("none");
    expect(a.discarded).toEqual(["mdm"]);
    expect(a.changes.mdm).toBe("intune_p1"); // the rules' pick
    expect(a.changes.identity).toBe("entra_p1");
    expect(a.reasons.identity).toBe("Conditional access for Microsoft 365.");
    expect(a.reasons.mdm).not.toBe("Made up.");
    expect(state.runs).toMatchObject([{ agentKey: "advisor", trigger: "manual", status: "succeeded", inputTokens: 1200, requestedById: "u1" }]);
  });

  it("falls back to the rules when the model call fails, and logs it", async () => {
    state.provider = fakeProvider([], { fail: true });
    const a = await runAdvisorAgent(cfg, ctx, "budget", { audience: "public", trigger: "website" });
    expect(a.status).toBe("fallback");
    expect(a.error).toMatch(/overloaded/);
    expect(a.changes.epp).toBe("none");
    expect(state.runs).toMatchObject([{ agentKey: "advisor", status: "fallback", engine: "Fake model" }]);
  });
});
