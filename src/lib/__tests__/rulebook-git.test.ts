import { describe, expect, it } from "vitest";

import { gitSyncSchema, sourceRequest } from "@/lib/rulebook/git-sync";
import { assertPublicUrl, isPrivateAddress, publicFetch } from "@/lib/net/public-fetch";

describe("rulebook Git sync", () => {
  it("reads from GitHub, GitLab or a plain https URL, with the token in the right header", () => {
    const gh = sourceRequest({ provider: "github", repo: "acme/policies", host: null, branch: "main", path: "helios/rule book.yaml" }, "tok");
    expect(gh.url).toBe("https://api.github.com/repos/acme/policies/contents/helios/rule%20book.yaml?ref=main");
    expect(gh.headers).toMatchObject({ accept: "application/vnd.github.raw+json", authorization: "Bearer tok" });
    const gl = sourceRequest({ provider: "gitlab", repo: "sec/policies", host: "git.acme.example", branch: "prod", path: "helios/rulebook.yaml" }, "tok");
    expect(gl.url).toBe("https://git.acme.example/api/v4/projects/sec%2Fpolicies/repository/files/helios%2Frulebook.yaml/raw?ref=prod");
    expect(gl.headers).toEqual({ "private-token": "tok" });
    expect(sourceRequest({ provider: "url", repo: "https://x.example/r.yaml", host: null, branch: "main", path: "" }, null)).toEqual({ url: "https://x.example/r.yaml", headers: {} });
  });

  it("checks the source before saving it", () => {
    expect(gitSyncSchema.safeParse({ provider: "github", repo: "acme" }).success).toBe(false);
    expect(gitSyncSchema.safeParse({ provider: "url", repo: "http://x.example/r.yaml" }).success).toBe(false);
    expect(gitSyncSchema.parse({ provider: "github", repo: "acme/policies", path: "/helios/r.yaml" }).path).toBe("helios/r.yaml");
  });
});

describe("fetching addresses people type", () => {
  it("refuses private, loopback and link-local addresses, IPv4 and IPv6", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "::1", "fe80::1", "fd00::5", "::ffff:10.0.0.1"]) expect(isPrivateAddress(ip)).toBe(true);
    for (const ip of ["203.0.113.10", "2001:db8::1", "8.8.8.8"]) expect(isPrivateAddress(ip)).toBe(false);
  });

  it("allows only https to public hosts, and won't follow redirects", async () => {
    await expect(assertPublicUrl("http://203.0.113.10/x")).rejects.toThrow(/https/);
    await expect(assertPublicUrl("https://169.254.169.254/latest/meta-data")).rejects.toThrow(/private or internal/);
    await expect(assertPublicUrl("https://[::1]/x")).rejects.toThrow(/private or internal/);
    const redirecting = (async () => new Response(null, { status: 302, headers: { location: "http://10.0.0.1/" } })) as unknown as typeof fetch;
    await expect(publicFetch("https://203.0.113.10/x", {}, redirecting)).rejects.toThrow(/redirect/);
  });
});
