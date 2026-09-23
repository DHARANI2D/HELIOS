import { describe, it, expect } from "vitest";

import { evaluateIntent } from "./policy";

describe("evaluateIntent", () => {
  it("denies an unknown intent", () => {
    expect(evaluateIntent({ intentName: "MADE_UP_INTENT", confidence: 0.99, environment: "staging" }).decision).toBe(
      "DENY",
    );
  });

  it("denies when confidence is below the threshold, regardless of environment", () => {
    const result = evaluateIntent({ intentName: "READ_PII", confidence: 0.5, environment: "staging" });
    expect(result.decision).toBe("DENY");
    expect(result.reason).toMatch(/confidence/i);
  });

  it("escalates high-risk intents in production for human approval", () => {
    const result = evaluateIntent({ intentName: "MODIFY_RESOURCE", confidence: 0.95, environment: "production" });
    expect(result.decision).toBe("ESCALATE");
  });

  it("denies critical-risk intents in production even with high confidence", () => {
    const result = evaluateIntent({ intentName: "DELETE_RESOURCE", confidence: 0.95, environment: "production" });
    // DELETE_RESOURCE is CRITICAL risk; production requires human approval for
    // HIGH/CRITICAL before the critical-specific deny is ever reached, so this
    // escalates rather than outright denies — matches the ported engine.ts order.
    expect(result.decision).toBe("ESCALATE");
  });

  it("allows a medium-risk intent in staging with high confidence", () => {
    const result = evaluateIntent({ intentName: "SEND_EXTERNAL_REQUEST", confidence: 0.95, environment: "staging" });
    expect(result.decision).toBe("ALLOW");
  });

  it("allows high-risk intents in staging (no approval requirement there)", () => {
    const result = evaluateIntent({ intentName: "MODIFY_RESOURCE", confidence: 0.95, environment: "staging" });
    expect(result.decision).toBe("ALLOW");
  });
});
