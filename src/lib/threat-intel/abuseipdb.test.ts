import { describe, it, expect, beforeEach, afterEach } from "vitest";

import { enrichIp } from "./abuseipdb";

describe("abuseipdb (mock fallback, no API key configured)", () => {
  const originalKey = process.env.ABUSEIPDB_API_KEY;

  beforeEach(() => {
    delete process.env.ABUSEIPDB_API_KEY;
  });

  afterEach(() => {
    if (originalKey) process.env.ABUSEIPDB_API_KEY = originalKey;
  });

  it("flags the known test Tor/C2 IP", async () => {
    const result = await enrichIp("185.220.101.5");
    expect(result.isMalicious).toBe(true);
    expect(result.abuseScore).toBeGreaterThan(25);
  });

  it("does not flag an arbitrary clean IP", async () => {
    const result = await enrichIp("8.8.8.8");
    expect(result.isMalicious).toBe(false);
    expect(result.abuseScore).toBe(0);
  });
});
