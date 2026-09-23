import { describe, it, expect } from "vitest";

import { verifyInvariant } from "./constitution";

describe("verifyInvariant", () => {
  it("blocks explicitly prohibited intents", () => {
    const result = verifyInvariant({ name: "DELETE_SYSTEM_CORE" });
    expect(result.safe).toBe(false);
    expect(result.violation).toBe("CONSTITUTION_BREACH");
  });

  it("is case-insensitive on the intent name", () => {
    expect(verifyInvariant({ name: "delete_system_core" }).safe).toBe(false);
  });

  it("blocks self-modification of core governance components", () => {
    const result = verifyInvariant({ name: "MODIFY_RESOURCE", target: "/aegis/policy/engine.py" });
    expect(result.safe).toBe(false);
    expect(result.violation).toBe("SELF_PROTECTION_FAULT");
  });

  it("allows modifying resources outside the protected path", () => {
    const result = verifyInvariant({ name: "MODIFY_RESOURCE", target: "staging-vm-01" });
    expect(result.safe).toBe(true);
  });

  it("allows ordinary, non-prohibited intents", () => {
    expect(verifyInvariant({ name: "READ_PII" }).safe).toBe(true);
  });
});
