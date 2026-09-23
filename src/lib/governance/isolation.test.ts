import { describe, it, expect } from "vitest";

import { getContasLevel, checkCapability } from "./isolation";

describe("getContasLevel", () => {
  it("maps 100 trust to level 10", () => {
    expect(getContasLevel(100)).toBe(10);
  });

  it("maps 0 trust to level 1", () => {
    expect(getContasLevel(0)).toBe(1);
  });

  it("clamps above 100 to level 10", () => {
    expect(getContasLevel(150)).toBe(10);
  });

  it("maps mid-range trust proportionally", () => {
    expect(getContasLevel(55)).toBe(6);
  });
});

describe("checkCapability", () => {
  it("locks out completely at 0 trust", () => {
    const result = checkCapability(0, "READ_PII");
    expect(result.allowed).toBe(false);
    expect(result.status).toBe("TOTAL_LOCKDOWN");
  });

  it("blocks all real actions in shadow/mock modes (levels 2-3)", () => {
    const result = checkCapability(25, "READ_PII");
    expect(result.allowed).toBe(false);
  });

  it("blocks write actions but not reads at mid trust (levels 4-6)", () => {
    const write = checkCapability(55, "MODIFY_RESOURCE");
    const read = checkCapability(55, "READ_PII");
    expect(write.allowed).toBe(false);
    expect(read.allowed).toBe(true);
  });

  it("allows everything at full trust", () => {
    const result = checkCapability(100, "DELETE_RESOURCE");
    expect(result.allowed).toBe(true);
    expect(result.status).toBe("UNRESTRICTED");
  });
});
