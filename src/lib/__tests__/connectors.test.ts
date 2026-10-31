import { describe, expect, it } from "vitest";

import { ConnectorError, createHttp, forgetToken } from "@/lib/connectors/http";
import { connectorForTool } from "@/lib/connectors/registry";
import type { ConnectorCtx, NativeConnector } from "@/lib/connectors/types";
import { defender } from "@/lib/connectors/vendors/defender";
import { entra } from "@/lib/connectors/vendors/entra";
import { crowdstrike } from "@/lib/connectors/vendors/crowdstrike";
import { sentinelone } from "@/lib/connectors/vendors/sentinelone";
import { okta } from "@/lib/connectors/vendors/okta";
import { cloudflare } from "@/lib/connectors/vendors/cloudflare";
import { exchange } from "@/lib/connectors/vendors/exchange";
import { parsePurgeTarget, purgeTarget, purgeTargetOfCase } from "@/lib/response/targets";

// Contract tests against each vendor's documented request and response
// shapes: a fake API that answers by method and URL, and records calls.

type Route = { method: string; match: RegExp; reply: Array<{ status?: number; body?: unknown; headers?: Record<string, string> }> };

function fakeApi(routes: Route[]) {
  const calls: Array<{ method: string; url: string; body?: unknown; headers: Record<string, string> }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const raw = typeof init?.body === "string" ? init.body : undefined;
    let body: unknown = raw;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      // form-encoded
    }
    calls.push({ method, url, body, headers: init?.headers as Record<string, string> });
    const route = routes.find((r) => r.method === method && r.match.test(url));
    if (!route) return new Response(JSON.stringify({ error: `no route for ${method} ${url}` }), { status: 599 });
    const next = route.reply.length > 1 ? route.reply.shift()! : route.reply[0];
    return new Response(next.body === undefined ? null : JSON.stringify(next.body), { status: next.status ?? 200, headers: next.headers });
  }) as typeof fetch;
  return { http: createHttp(fetchImpl, { maxWaitMs: 1 }), calls };
}

const ctx = (http: ConnectorCtx["http"], config: Record<string, string>, secrets: Record<string, string>, key = Math.random().toString(36)): ConnectorCtx => ({ http, config, secrets, cacheKey: key });
const req = (c: ConnectorCtx, action: Parameters<NativeConnector["preflight"]>[0]["action"], target: string) => ({ action, target, ctx: c, idempotencyKey: "ra_123", comment: "Test case" });
const MS_TOKEN: Route = { method: "POST", match: /login\.microsoftonline\.com\/tid\/oauth2\/v2\.0\/token/, reply: [{ body: { access_token: "ms-token", expires_in: 3599 } }] };
const MS = { tenantId: "tid", clientId: "cid" };

describe("HTTP client", () => {
  it("retries a 429 after Retry-After and reports failures by host and status", async () => {
    const { http, calls } = fakeApi([{ method: "GET", match: /x\.example/, reply: [{ status: 429, headers: { "retry-after": "0" } }, { body: { ok: 1 } }] }]);
    expect((await http("https://x.example/a")).data).toEqual({ ok: 1 });
    expect(calls).toHaveLength(2);
    const { http: h2 } = fakeApi([{ method: "GET", match: /x\.example/, reply: [{ status: 401, body: { error: "invalid token" } }] }]);
    await expect(h2("https://x.example/a")).rejects.toThrow(/x\.example answered HTTP 401: .*invalid token/);
    await expect(h2("https://x.example/a")).rejects.toBeInstanceOf(ConnectorError);
  });

  it("maps catalog tools to connectors", () => {
    expect(connectorForTool("defender_endpoint_p2")?.key).toBe("defender_endpoint");
    expect(connectorForTool("okta_workforce")?.key).toBe("okta");
    expect(connectorForTool("wazuh")).toBeUndefined();
  });
});

describe("Microsoft Defender for Endpoint", () => {
  it("isolates by device name, follows the machine action until it succeeds", async () => {
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /\/api\/machines\?\$filter=computerDnsName%20eq%20'ws-fin-07'/, reply: [{ body: { value: [] } }] },
      { method: "GET", match: /\/api\/machines\?\$filter=startswith/, reply: [{ body: { value: [{ id: "m1", computerDnsName: "ws-fin-07.corp.example", healthStatus: "Active" }] } }] },
      { method: "POST", match: /\/api\/machines\/m1\/isolate$/, reply: [{ status: 201, body: { id: "act1", type: "Isolate", status: "Pending", machineId: "m1" } }] },
      { method: "GET", match: /\/api\/machineactions\/act1$/, reply: [{ body: { id: "act1", type: "Isolate", status: "InProgress" } }, { body: { id: "act1", type: "Isolate", status: "Succeeded" } }] },
    ]);
    const c = ctx(http, { ...MS, isolationType: "Selective" }, { clientSecret: "s" });
    const pre = await defender.preflight(req(c, "ISOLATE_HOST", "WS-FIN-07"));
    expect(pre).toMatchObject({ ok: true, resolved: { id: "m1", name: "ws-fin-07.corp.example" } });
    const done = await defender.execute(req(c, "ISOLATE_HOST", "WS-FIN-07"), pre.ok ? pre.resolved : (null as never));
    expect(done).toMatchObject({ ref: { machineActionId: "act1", machineId: "m1" }, confirmed: false });
    const posted = calls.find((x) => x.url.endsWith("/isolate"))!;
    expect(posted.body).toEqual({ Comment: "Test case [HELIOS ra_123]", IsolationType: "Selective" });
    expect(posted.headers.authorization).toBe("Bearer ms-token");
    expect((await defender.verify(req(c, "ISOLATE_HOST", ""), done.ref)).state).toBe("pending");
    expect((await defender.verify(req(c, "ISOLATE_HOST", ""), done.ref)).state).toBe("confirmed");
    // The token was fetched once and reused.
    expect(calls.filter((x) => x.url.includes("oauth2")).length).toBe(1);
  });

  it("refuses an unknown or ambiguous device and follows an already-running request", async () => {
    const { http } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /computerDnsName%20eq%20'ghost'/, reply: [{ body: { value: [] } }] },
      { method: "GET", match: /startswith\(computerDnsName%2C'ghost\.'\)/, reply: [{ body: { value: [] } }] },
      { method: "GET", match: /computerDnsName%20eq%20'twin.corp'/, reply: [{ body: { value: [{ id: "a", computerDnsName: "twin.corp" }, { id: "b", computerDnsName: "twin.corp" }] } }] },
      { method: "POST", match: /\/api\/machines\/m2\/unisolate$/, reply: [{ status: 400, body: { error: { code: "ActiveRequestAlreadyExists" } } }] },
      { method: "GET", match: /\/api\/machineactions\?\$filter=machineId/, reply: [{ body: { value: [{ id: "act9", type: "Unisolate", status: "InProgress" }] } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    expect(await defender.preflight(req(c, "ISOLATE_HOST", "ghost"))).toMatchObject({ ok: false, reason: expect.stringMatching(/no device/) });
    expect(await defender.preflight(req(c, "ISOLATE_HOST", "twin.corp"))).toMatchObject({ ok: false, reason: expect.stringMatching(/2 devices/) });
    const done = await defender.execute(req(c, "RELEASE_HOST", "m2"), { id: "m2", name: "m2" });
    expect(done.ref.machineActionId).toBe("act9");
  });

  it("blocks a file hash and an IP with indicators", async () => {
    const hash = "a".repeat(64);
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /\/api\/indicators\?\$filter=/, reply: [{ body: { value: [] } }, { body: { value: [{ id: 7, indicatorValue: hash, action: "BlockAndRemediate" }] } }] },
      { method: "POST", match: /\/api\/indicators$/, reply: [{ body: { id: 7, indicatorValue: hash, action: "BlockAndRemediate" } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    expect(await defender.preflight(req(c, "QUARANTINE_FILE", "not-a-hash"))).toMatchObject({ ok: false });
    const pre = await defender.preflight(req(c, "QUARANTINE_FILE", hash));
    expect(pre).toMatchObject({ ok: true, alreadyDone: false });
    const done = await defender.execute(req(c, "QUARANTINE_FILE", hash), pre.ok ? pre.resolved : (null as never));
    expect(calls.find((x) => x.method === "POST" && x.url.endsWith("/api/indicators"))!.body).toMatchObject({ indicatorValue: hash, indicatorType: "FileSha256", action: "BlockAndRemediate" });
    expect((await defender.verify(req(c, "QUARANTINE_FILE", ""), done.ref)).state).toBe("confirmed");
  });
});

describe("Microsoft Entra ID", () => {
  it("disables by sign-in name, revokes sessions, and confirms accountEnabled", async () => {
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /graph\.microsoft\.com\/v1\.0\/users\/jdoe%40corp\.example\?/, reply: [{ body: { id: "u1", userPrincipalName: "jdoe@corp.example", accountEnabled: true } }] },
      { method: "PATCH", match: /\/users\/u1$/, reply: [{ status: 204 }] },
      { method: "POST", match: /\/users\/u1\/revokeSignInSessions$/, reply: [{ body: { value: true } }] },
      { method: "GET", match: /\/users\/u1\?/, reply: [{ body: { id: "u1", userPrincipalName: "jdoe@corp.example", accountEnabled: false } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    const pre = await entra.preflight(req(c, "DISABLE_USER", "jdoe@corp.example"));
    expect(pre).toMatchObject({ ok: true, alreadyDone: false });
    const done = await entra.execute(req(c, "DISABLE_USER", "jdoe@corp.example"), pre.ok ? pre.resolved : (null as never));
    expect(calls.find((x) => x.method === "PATCH")!.body).toEqual({ accountEnabled: false });
    expect(calls.some((x) => x.url.endsWith("/revokeSignInSessions"))).toBe(true);
    expect((await entra.verify(req(c, "DISABLE_USER", ""), done.ref)).state).toBe("confirmed");
  });

  it("finds DOMAIN\\user by on-premises name with an advanced query, and refuses ambiguity", async () => {
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /\/v1\.0\/users\?\$filter=onPremisesSamAccountName%20eq%20'jdoe'/, reply: [{ body: { value: [{ id: "u1", userPrincipalName: "jdoe@corp.example", accountEnabled: false }] } }] },
      { method: "GET", match: /\/v1\.0\/users\?\$filter=onPremisesSamAccountName%20eq%20'sam'/, reply: [{ body: { value: [{ id: "a" }, { id: "b" }] } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    expect(await entra.preflight(req(c, "DISABLE_USER", "CORP\\jdoe"))).toMatchObject({ ok: true, alreadyDone: true });
    expect(calls.at(-1)!.headers.ConsistencyLevel).toBe("eventual");
    expect(await entra.preflight(req(c, "DISABLE_USER", "sam"))).toMatchObject({ ok: false });
  });
});

describe("CrowdStrike Falcon", () => {
  it("contains a host and confirms when Falcon reports it contained", async () => {
    forgetToken("cs:falcon");
    const { http, calls } = fakeApi([
      { method: "POST", match: /api\.eu-1\.crowdstrike\.com\/oauth2\/token/, reply: [{ status: 201, body: { access_token: "cs-token", expires_in: 1799 } }] },
      { method: "GET", match: /devices\/queries\/devices\/v1\?filter=hostname%3A'WS-07'/, reply: [{ body: { resources: ["aid1"] } }] },
      { method: "GET", match: /devices\/entities\/devices\/v2\?ids=aid1/, reply: [{ body: { resources: [{ device_id: "aid1", hostname: "WS-07", status: "normal" }] } }, { body: { resources: [{ device_id: "aid1", hostname: "WS-07", status: "containment_pending" }] } }, { body: { resources: [{ device_id: "aid1", hostname: "WS-07", status: "contained" }] } }] },
      { method: "POST", match: /devices-actions\/v2\?action_name=contain/, reply: [{ status: 202, body: { resources: [{ id: "aid1" }] } }] },
    ]);
    const c = ctx(http, { baseUrl: "https://api.eu-1.crowdstrike.com", clientId: "id" }, { clientSecret: "s" }, "cs");
    const pre = await crowdstrike.preflight(req(c, "ISOLATE_HOST", "WS-07"));
    expect(pre).toMatchObject({ ok: true, alreadyDone: false, resolved: { id: "aid1" } });
    const done = await crowdstrike.execute(req(c, "ISOLATE_HOST", "WS-07"), pre.ok ? pre.resolved : (null as never));
    expect(calls.find((x) => x.url.includes("devices-actions"))!.body).toEqual({ ids: ["aid1"] });
    expect((await crowdstrike.verify(req(c, "ISOLATE_HOST", ""), done.ref)).state).toBe("pending");
    expect((await crowdstrike.verify(req(c, "ISOLATE_HOST", ""), done.ref)).state).toBe("confirmed");
  });
});

describe("SentinelOne", () => {
  it("disconnects an agent with an ApiToken header and confirms networkStatus", async () => {
    const { http, calls } = fakeApi([
      { method: "GET", match: /\/web\/api\/v2\.1\/agents\?computerName=WS-07/, reply: [{ body: { data: [{ id: "ag1", computerName: "WS-07", networkStatus: "connected" }] } }] },
      { method: "POST", match: /\/agents\/actions\/disconnect$/, reply: [{ body: { data: { affected: 1 } } }] },
      { method: "GET", match: /\/agents\?ids=ag1/, reply: [{ body: { data: [{ id: "ag1", computerName: "WS-07", networkStatus: "disconnected" }] } }] },
    ]);
    const c = ctx(http, { consoleUrl: "https://usea1-acme.sentinelone.net/" }, { apiToken: "tok" });
    const pre = await sentinelone.preflight(req(c, "ISOLATE_HOST", "WS-07"));
    const done = await sentinelone.execute(req(c, "ISOLATE_HOST", "WS-07"), pre.ok ? pre.resolved : (null as never));
    expect(calls[1].body).toEqual({ filter: { ids: ["ag1"] } });
    expect(calls[0].headers.authorization).toBe("ApiToken tok");
    expect((await sentinelone.verify(req(c, "ISOLATE_HOST", ""), done.ref)).state).toBe("confirmed");
  });

  it("fails when SentinelOne affects no agent", async () => {
    const { http } = fakeApi([{ method: "POST", match: /\/agents\/actions\/connect$/, reply: [{ body: { data: { affected: 0 } } }] }]);
    const c = ctx(http, { consoleUrl: "https://x.sentinelone.net" }, { apiToken: "tok" });
    await expect(sentinelone.execute(req(c, "RELEASE_HOST", "WS-07"), { id: "ag1", name: "WS-07" })).rejects.toThrow(/0 agents affected/);
  });
});

describe("Okta", () => {
  it("suspends an active user, clears sessions, and refuses ones that can't be suspended", async () => {
    const { http, calls } = fakeApi([
      { method: "GET", match: /\/api\/v1\/users\/jdoe%40corp\.example$/, reply: [{ body: { id: "00u1", status: "ACTIVE", profile: { login: "jdoe@corp.example" } } }] },
      { method: "GET", match: /\/api\/v1\/users\/gone%40corp\.example$/, reply: [{ status: 404, body: { errorCode: "E0000007" } }] },
      { method: "GET", match: /\/api\/v1\/users\/old%40corp\.example$/, reply: [{ body: { id: "00u2", status: "DEPROVISIONED", profile: { login: "old@corp.example" } } }] },
      { method: "POST", match: /\/users\/00u1\/lifecycle\/suspend$/, reply: [{ body: {} }] },
      { method: "DELETE", match: /\/users\/00u1\/sessions$/, reply: [{ status: 204 }] },
      { method: "GET", match: /\/api\/v1\/users\/00u1$/, reply: [{ body: { id: "00u1", status: "SUSPENDED", profile: { login: "jdoe@corp.example" } } }] },
    ]);
    const c = ctx(http, { orgUrl: "https://acme.okta.com" }, { apiToken: "tok" });
    expect(await okta.preflight(req(c, "DISABLE_USER", "gone@corp.example"))).toMatchObject({ ok: false });
    expect(await okta.preflight(req(c, "DISABLE_USER", "old@corp.example"))).toMatchObject({ ok: false, reason: expect.stringMatching(/deprovisioned/) });
    const pre = await okta.preflight(req(c, "DISABLE_USER", "jdoe@corp.example"));
    const done = await okta.execute(req(c, "DISABLE_USER", "jdoe@corp.example"), pre.ok ? pre.resolved : (null as never));
    expect(calls[0].headers.authorization).toBe("SSWS tok");
    expect(calls.some((x) => x.method === "DELETE" && x.url.endsWith("/sessions"))).toBe(true);
    expect((await okta.verify(req(c, "DISABLE_USER", ""), done.ref)).state).toBe("confirmed");
  });
});

describe("Cloudflare", () => {
  it("blocks an IP across the account and confirms the rule, then removes it", async () => {
    const rule = { id: "r1", mode: "block", configuration: { target: "ip", value: "203.0.113.9" } };
    const { http, calls } = fakeApi([
      { method: "GET", match: /accounts\/acc\/firewall\/access_rules\/rules\?mode=block&configuration\.target=ip&configuration\.value=203\.0\.113\.9/, reply: [{ body: { success: true, result: [] } }, { body: { success: true, result: [rule] } }, { body: { success: true, result: [rule] } }, { body: { success: true, result: [] } }] },
      { method: "POST", match: /accounts\/acc\/firewall\/access_rules\/rules$/, reply: [{ body: { success: true, result: rule } }] },
      { method: "DELETE", match: /rules\/r1$/, reply: [{ body: { success: true, result: { id: "r1" } } }] },
    ]);
    const c = ctx(http, { accountId: "acc" }, { apiToken: "tok" });
    expect(await cloudflare.preflight(req(c, "BLOCK_IP", "not-an-ip"))).toMatchObject({ ok: false });
    const pre = await cloudflare.preflight(req(c, "BLOCK_IP", "203.0.113.9"));
    const done = await cloudflare.execute(req(c, "BLOCK_IP", "203.0.113.9"), pre.ok ? pre.resolved : (null as never));
    expect(calls.find((x) => x.method === "POST")!.body).toMatchObject({ mode: "block", configuration: { target: "ip", value: "203.0.113.9" } });
    expect((await cloudflare.verify(req(c, "BLOCK_IP", ""), done.ref)).state).toBe("confirmed");
    const unpre = await cloudflare.preflight(req(c, "UNBLOCK_IP", "203.0.113.9"));
    expect(unpre).toMatchObject({ ok: true, resolved: { id: "r1" }, alreadyDone: false });
    const undone = await cloudflare.execute(req(c, "UNBLOCK_IP", "203.0.113.9"), unpre.ok ? unpre.resolved : (null as never));
    expect((await cloudflare.verify(req(c, "UNBLOCK_IP", ""), undone.ref)).state).toBe("confirmed");
  });
});

describe("Microsoft Entra ID password reset", () => {
  it("sets a random password to change at next sign-in, ends sessions, and confirms both", async () => {
    const at = new Date();
    const later = new Date(at.getTime() + 5000).toISOString();
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /\/users\/jdoe%40corp\.example\?/, reply: [{ body: { id: "u1", userPrincipalName: "jdoe@corp.example", accountEnabled: true, onPremisesSyncEnabled: null } }] },
      { method: "GET", match: /\/users\/hybrid%40corp\.example\?/, reply: [{ body: { id: "u2", userPrincipalName: "hybrid@corp.example", accountEnabled: true, onPremisesSyncEnabled: true } }] },
      { method: "PATCH", match: /\/users\/u1$/, reply: [{ status: 204 }] },
      { method: "POST", match: /\/users\/u1\/revokeSignInSessions$/, reply: [{ body: { value: true } }] },
      { method: "GET", match: /\/users\/u1\?\$select=id,lastPasswordChangeDateTime/, reply: [{ body: { id: "u1", lastPasswordChangeDateTime: "2020-01-01T00:00:00Z", signInSessionsValidFromDateTime: later } }, { body: { id: "u1", lastPasswordChangeDateTime: later, signInSessionsValidFromDateTime: later } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    expect(await entra.preflight(req(c, "RESET_PASSWORD", "hybrid@corp.example"))).toMatchObject({ ok: false, reason: expect.stringMatching(/on-premises/) });
    const pre = await entra.preflight(req(c, "RESET_PASSWORD", "jdoe@corp.example"));
    expect(pre).toMatchObject({ ok: true });
    const done = await entra.execute(req(c, "RESET_PASSWORD", "jdoe@corp.example"), pre.ok ? pre.resolved : (null as never));
    const body = calls.find((x) => x.method === "PATCH")!.body as { passwordProfile: { forceChangePasswordNextSignIn: boolean; password: string } };
    expect(body.passwordProfile.forceChangePasswordNextSignIn).toBe(true);
    expect(body.passwordProfile.password).toMatch(/^.{28,}$/);
    // The password isn't kept anywhere HELIOS writes.
    expect(JSON.stringify(done)).not.toContain(body.passwordProfile.password);
    expect(calls.some((x) => x.url.endsWith("/u1/revokeSignInSessions"))).toBe(true);
    expect((await entra.verify(req(c, "RESET_PASSWORD", ""), done.ref)).state).toBe("pending");
    expect((await entra.verify(req(c, "RESET_PASSWORD", ""), done.ref)).state).toBe("confirmed");
  });
});

describe("Microsoft Exchange Online", () => {
  const target = purgeTarget("<abc@mail.evil.example>", ["a@corp.example", "B@corp.example", "gone@corp.example"]);

  it("reads purge targets back, and builds one from an email case", () => {
    expect(target).toBe("<abc@mail.evil.example> to a@corp.example, b@corp.example, gone@corp.example");
    expect(parsePurgeTarget(target)).toEqual({ messageId: "<abc@mail.evil.example>", recipients: ["a@corp.example", "b@corp.example", "gone@corp.example"] });
    expect(parsePurgeTarget("abc@x to y@z")).toBeNull();
    expect(purgeTargetOfCase({ email: { messageId: "m1@x.example", to: "Ann <ann@corp.example>, bob@corp.example", cc: "ann@corp.example" } })).toBe("<m1@x.example> to ann@corp.example, bob@corp.example");
    expect(purgeTargetOfCase({ email: { to: "ann@corp.example" } })).toBeNull();
  });

  it("finds each copy by Message-ID, moves it to Recoverable Items, and confirms none is left", async () => {
    const found = { value: [{ id: "m-a" }] };
    const { http, calls } = fakeApi([
      MS_TOKEN,
      { method: "GET", match: /\/users\/a%40corp\.example\/messages\?\$filter=internetMessageId%20eq%20'%3Cabc%40mail\.evil\.example%3E'/, reply: [{ body: found }, { body: found }, { body: found }, { body: { value: [] } }] },
      { method: "GET", match: /\/users\/b%40corp\.example\/messages\?/, reply: [{ body: { value: [{ id: "m-b1" }, { id: "m-b2" }] } }, { body: { value: [{ id: "m-b1" }, { id: "m-b2" }] } }, { body: { value: [] } }] },
      { method: "GET", match: /\/users\/gone%40corp\.example\/messages\?/, reply: [{ status: 404, body: { error: { code: "ErrorInvalidUser" } } }] },
      { method: "POST", match: /\/messages\/m-[ab]\d?\/move$/, reply: [{ status: 201, body: { id: "moved" } }] },
    ]);
    const c = ctx(http, MS, { clientSecret: "s" });
    const pre = await exchange.preflight(req(c, "PURGE_EMAIL", target));
    expect(pre).toMatchObject({ ok: true, alreadyDone: false, resolved: { name: "<abc@mail.evil.example> (3 copies in 2 of 3 mailboxes)" } });
    const done = await exchange.execute(req(c, "PURGE_EMAIL", target), pre.ok ? pre.resolved : (null as never));
    const moves = calls.filter((x) => x.method === "POST" && x.url.endsWith("/move"));
    expect(moves).toHaveLength(3);
    expect(moves.every((m) => (m.body as { destinationId: string }).destinationId === "recoverableitemsdeletions")).toBe(true);
    expect((await exchange.verify(req(c, "PURGE_EMAIL", target), done.ref)).state).toBe("pending");
    expect((await exchange.verify(req(c, "PURGE_EMAIL", target), done.ref)).state).toBe("confirmed");
  });

  it("calls a message that's in no mailbox already gone, and refuses when no recipient has a mailbox", async () => {
    const { http } = fakeApi([MS_TOKEN, { method: "GET", match: /\/users\/a%40corp\.example\/messages/, reply: [{ body: { value: [] } }] }, { method: "GET", match: /\/users\/x%40other\.example\/messages/, reply: [{ status: 404 }] }]);
    const c = ctx(http, MS, { clientSecret: "s" });
    expect(await exchange.preflight(req(c, "PURGE_EMAIL", purgeTarget("<abc@x>", ["a@corp.example"])))).toMatchObject({ ok: true, alreadyDone: true });
    expect(await exchange.preflight(req(c, "PURGE_EMAIL", purgeTarget("<abc@x>", ["x@other.example"])))).toMatchObject({ ok: false });
  });
});

describe("CrowdStrike Falcon file block", () => {
  const sha = "a".repeat(64);
  it("blocks a hash with a prevent IOC on every platform and confirms it", async () => {
    forgetToken("cs-ioc:falcon");
    const { http, calls } = fakeApi([
      { method: "POST", match: /oauth2\/token/, reply: [{ status: 201, body: { access_token: "cs-token", expires_in: 1799 } }] },
      { method: "GET", match: /iocs\/combined\/indicator\/v1\?filter=type%3A'sha256'%2Bvalue%3A'a{64}'/, reply: [{ body: { resources: [] } }, { body: { resources: [{ id: "ioc1", action: "prevent", value: sha }] } }] },
      { method: "POST", match: /iocs\/entities\/indicators\/v1$/, reply: [{ status: 201, body: { resources: [{ id: "ioc1" }] } }] },
    ]);
    const c = ctx(http, { clientId: "id" }, { clientSecret: "s" }, "cs-ioc");
    expect(await crowdstrike.preflight(req(c, "QUARANTINE_FILE", "b".repeat(40)))).toMatchObject({ ok: false, reason: expect.stringMatching(/SHA-256 or MD5/) });
    const pre = await crowdstrike.preflight(req(c, "QUARANTINE_FILE", sha.toUpperCase()));
    expect(pre).toMatchObject({ ok: true, alreadyDone: false });
    const done = await crowdstrike.execute(req(c, "QUARANTINE_FILE", sha.toUpperCase()), pre.ok ? pre.resolved : (null as never));
    const body = calls.find((x) => x.method === "POST" && x.url.endsWith("/indicators/v1"))!.body as { comment: string; indicators: Array<Record<string, unknown>> };
    expect(body.indicators[0]).toMatchObject({ type: "sha256", value: sha, action: "prevent", platforms: ["windows", "mac", "linux"], applied_globally: true, source: "HELIOS" });
    expect((await crowdstrike.verify(req(c, "QUARANTINE_FILE", sha), done.ref)).state).toBe("confirmed");
  });
});
