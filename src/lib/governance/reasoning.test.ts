import { describe, it, expect } from "vitest";

import { analyzeReasoning, generateReasoningHash } from "./reasoning";

describe("analyzeReasoning", () => {
  it("flags goal drift when the final intent isn't supported by the reasoning chain", () => {
    const result = analyzeReasoning(
      [
        "Analyzing disk space utilization",
        "Identified old log files consuming 2TB",
        "Recommending cleanup of temporary archives",
      ],
      "delete_resource",
    );
    expect(result.safe).toBe(false);
    expect(result.threat).toBe("GOAL_DRIFT");
  });

  it("flags insufficient reasoning depth even when the intent matches", () => {
    const result = analyzeReasoning(["execute the delete_resource action now"], "delete_resource");
    expect(result.safe).toBe(false);
    expect(result.threat).toBe("LOW_REASONING_QUALITY");
  });

  it("passes when the chain has 2+ steps and supports the final intent", () => {
    const result = analyzeReasoning(
      ["Identified stale backup files", "Proceeding to delete_resource as authorized"],
      "delete_resource",
    );
    expect(result.safe).toBe(true);
  });
});

describe("generateReasoningHash", () => {
  it("is deterministic for the same input", () => {
    const a = generateReasoningHash(["step one", "step two"]);
    const b = generateReasoningHash(["step one", "step two"]);
    expect(a).toBe(b);
  });

  it("differs when the reasoning changes", () => {
    const a = generateReasoningHash(["step one"]);
    const b = generateReasoningHash(["step two"]);
    expect(a).not.toBe(b);
  });
});
