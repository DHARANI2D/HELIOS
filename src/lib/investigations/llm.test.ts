import { describe, it, expect } from "vitest";

import { TIER_MODEL, invokeAgent } from "./llm";

describe("TIER_MODEL (AI model marketplace tier -> Claude model mapping)", () => {
  it("has a distinct model for each cloud tier", () => {
    const models = Object.values(TIER_MODEL);
    expect(new Set(models).size).toBe(models.length);
  });

  it("keeps PROFESSIONAL as the pre-existing default model — SELF_HOSTED/ESSENTIAL/ENTERPRISE are additive, not a behavior change for orgs that don't pick a tier", () => {
    expect(TIER_MODEL.PROFESSIONAL).toBe("claude-sonnet-4-5");
  });

  it("covers every cloud tier (everything except SELF_HOSTED, which never reaches Anthropic)", () => {
    expect(Object.keys(TIER_MODEL).sort()).toEqual(["ENTERPRISE", "ESSENTIAL", "PROFESSIONAL"]);
  });
});

describe("invokeAgent tier handling (no live provider keys in this sandbox — exercises the fallback paths)", () => {
  it("never throws for any tier and always returns a non-empty string", async () => {
    for (const tier of ["ESSENTIAL", "PROFESSIONAL", "ENTERPRISE", "SELF_HOSTED"] as const) {
      const result = await invokeAgent("You are a triage agent.", "Alert details", { tier });
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    }
  });

  it("SELF_HOSTED with no reachable Ollama endpoint degrades to the mock response rather than throwing", async () => {
    const result = await invokeAgent("You are a triage agent.", "Alert details", {
      tier: "SELF_HOSTED",
      selfHostedOllamaUrl: "http://127.0.0.1:1", // nothing listens here
    });
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});
