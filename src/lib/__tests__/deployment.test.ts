import { describe, expect, it } from "vitest";

import { jobGroups } from "@/lib/jobs/scheduler";
import { addressFrom, trustedProxies } from "@/lib/rate-limit";
import { contentSecurityPolicy, newNonce, servedOverHttps, staticSecurityHeaders } from "@/lib/security-headers";

describe("visitor address behind proxies", () => {
  it("takes the entry the nearest trusted proxy added, not what the visitor sent", () => {
    // The visitor forged 1.2.3.4; the load balancer appended the real address.
    expect(addressFrom("1.2.3.4, 203.0.113.9", 1)).toBe("203.0.113.9");
    // Load balancer then ingress: the visitor is second from the right.
    expect(addressFrom("1.2.3.4, 203.0.113.9, 10.0.0.5", 2)).toBe("203.0.113.9");
    expect(addressFrom("203.0.113.9", 1)).toBe("203.0.113.9");
    // Fewer entries than proxies: the request skipped the outer one.
    expect(addressFrom("10.0.0.7", 2)).toBe("10.0.0.7");
    expect(addressFrom(null, 1)).toBe("unknown");
    // No proxy: the header can't be trusted at all.
    expect(addressFrom("1.2.3.4", 0)).toBe("unknown");
  });

  it("reads the number of proxies, falling back to one", () => {
    expect(trustedProxies({})).toBe(1);
    expect(trustedProxies({ HELIOS_TRUSTED_PROXIES: "2" })).toBe(2);
    expect(trustedProxies({ HELIOS_TRUSTED_PROXIES: "0" })).toBe(0);
    expect(trustedProxies({ HELIOS_TRUSTED_PROXIES: "lots" })).toBe(1);
    expect(trustedProxies({ HELIOS_TRUSTED_PROXIES: "-1" })).toBe(1);
  });
});

describe("security headers", () => {
  it("allows only scripts with the response's nonce", () => {
    const nonce = newNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(newNonce()).not.toBe(nonce);
    const csp = contentSecurityPolicy(nonce, { AUTH_URL: "https://soc.example.com" });
    expect(csp).toContain(`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`);
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(csp).not.toContain("unsafe-eval");
    for (const d of ["object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "upgrade-insecure-requests"]) expect(csp).toContain(d);
    // A plain-http test install isn't told to upgrade requests or pin https.
    expect(contentSecurityPolicy(nonce, { AUTH_URL: "http://localhost:3000" })).not.toContain("upgrade-insecure-requests");
    expect(servedOverHttps({ AUTH_URL: "http://localhost:3000" })).toBe(false);
    expect(servedOverHttps({ AUTH_URL: "https://soc.example.com" })).toBe(true);
  });

  it("sends the fixed hardening headers on every response", () => {
    const keys = Object.fromEntries(staticSecurityHeaders().map((h) => [h.key, h.value]));
    expect(keys["X-Content-Type-Options"]).toBe("nosniff");
    expect(keys["X-Frame-Options"]).toBe("DENY");
    expect(keys["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    expect(keys["Permissions-Policy"]).toContain("camera=()");
  });
});

describe("job groups per process", () => {
  it("reads HELIOS_JOBS, or falls back", () => {
    expect(jobGroups(["ingest"], undefined)).toEqual(["ingest"]);
    expect(jobGroups(["core", "ingest"], "")).toEqual(["core", "ingest"]);
    expect(jobGroups(["core", "ingest"], "none")).toEqual([]);
    expect(jobGroups(["ingest"], "core, ingest")).toEqual(["core", "ingest"]);
    expect(jobGroups([], "INGEST")).toEqual(["ingest"]);
    expect(() => jobGroups([], "core,reports")).toThrow(/unknown job group reports/);
  });
});
