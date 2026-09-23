import { describe, it, expect, beforeEach, afterEach } from "vitest";

import { virustotal } from "./virustotal";

// This environment has no route to VirusTotal's API, and no API key is
// configured — every call here exercises the mock-fallback path, which is
// deterministic and safe to assert on directly.

describe("virustotal (mock fallback, no API key configured)", () => {
  const originalKey = process.env.VIRUSTOTAL_API_KEY;

  beforeEach(() => {
    delete process.env.VIRUSTOTAL_API_KEY;
  });

  afterEach(() => {
    if (originalKey) process.env.VIRUSTOTAL_API_KEY = originalKey;
  });

  it("flags known test-malicious values", async () => {
    const result = await virustotal.enrichIp("185.220.101.5");
    expect(result.isMalicious).toBe(true);
    expect(result.maliciousCount).toBeGreaterThan(0);
  });

  it("does not flag an arbitrary clean-looking value", async () => {
    const result = await virustotal.enrichDomain("example.com");
    expect(result.isMalicious).toBe(false);
    expect(result.maliciousCount).toBe(0);
  });

  it("flags the known test-malicious domain and hash", async () => {
    expect((await virustotal.enrichDomain("update-service.net")).isMalicious).toBe(true);
    expect((await virustotal.enrichHash("sha256_abc")).isMalicious).toBe(true);
  });
});
