import { describe, it, expect } from "vitest";

import { deriveVerdict, classifyThreat } from "./scoring";

describe("deriveVerdict", () => {
  it("classifies below 31 as benign", () => {
    expect(deriveVerdict(0)).toBe("benign");
    expect(deriveVerdict(30)).toBe("benign");
  });

  it("classifies 31-70 as suspicious", () => {
    expect(deriveVerdict(31)).toBe("suspicious");
    expect(deriveVerdict(70)).toBe("suspicious");
  });

  it("classifies 71+ as malicious", () => {
    expect(deriveVerdict(71)).toBe("malicious");
    expect(deriveVerdict(500)).toBe("malicious");
  });
});

describe("classifyThreat", () => {
  it("classifies credential-harvesting phishing", () => {
    const result = classifyThreat(["Content suggests credential harvesting intent (login/password keywords)"]);
    expect(result?.threatType).toBe("Phishing");
    expect(result?.threatCategory).toBe("Credential Harvesting");
  });

  it("classifies malware when malicious/macro keywords are present", () => {
    const result = classifyThreat(["Auto-executing macro with suspicious calls detected"]);
    expect(result?.threatType).toBe("Malware");
  });

  it("returns null when no reasons hint at a specific threat type", () => {
    expect(classifyThreat([])).toBeNull();
    expect(classifyThreat(["Suspicious TLD detected"])).toBeNull();
  });
});
