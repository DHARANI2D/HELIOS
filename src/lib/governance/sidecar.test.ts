import { describe, it, expect } from "vitest";

import { processAction } from "./sidecar";

describe("processAction (sidecar pipeline)", () => {
  it("blocks at the CONSTITUTION layer for a prohibited intent, before any other check runs", () => {
    const result = processAction({ name: "DELETE_SYSTEM_CORE" }, "production");
    expect(result.decision).toBe("DENY");
    expect(result.layer).toBe("CONSTITUTION");
  });

  it("blocks at the REASONING layer for a goal-drift chain", () => {
    const result = processAction(
      {
        name: "DELETE_RESOURCE",
        reasoning: ["Recommending cleanup of temp archives", "Nothing about deletion here"],
      },
      "production",
    );
    expect(result.decision).toBe("DENY");
    expect(result.layer).toBe("REASONING");
  });

  it("blocks at the DLP layer when the payload contains PII", () => {
    const result = processAction(
      {
        name: "SEND_EXTERNAL_REQUEST",
        url: "https://malicious-collector.dark/upload",
        payload_sample: { customer_emails: ["user@example.com"] },
        confidence: 0.95,
      },
      "production",
    );
    expect(result.decision).toBe("DENY");
    expect(result.layer).toBe("DLP");
  });

  it("falls through to the POLICY layer and allows a clean, high-confidence, low-risk action", () => {
    const result = processAction({ name: "READ_PII", confidence: 0.95 }, "staging");
    expect(result.decision).toBe("ALLOW");
    expect(result.layer).toBe("POLICY");
  });
});
