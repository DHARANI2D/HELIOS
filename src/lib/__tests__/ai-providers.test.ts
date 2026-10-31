import { describe, expect, it } from "vitest";
import { z } from "zod";

import { anthropicProvider, bedrockProvider, parseBedrockAuth, usageOf } from "@/lib/ai/anthropic";
import { azureBaseUrl, openAiCompatibleProvider, reason } from "@/lib/ai/openai-compatible";
import { bedrockModelProblem } from "@/lib/ai/catalog";
import { providerColumns, providerInputSchema, providerSecret } from "@/lib/ai/provider-input";
import { addUsage } from "@/lib/ai/provider";
import { whyNot, type Candidate } from "@/lib/ai/gateway";
import { clientEndpointFetch } from "@/lib/ai/resolve";
import { inIndia, regionSatisfies } from "@/lib/regions";
import { priceKey, runCost } from "@/lib/pricing/service";

// A stand-in for the network: records each request and answers with the
// next canned body.
function recorder(...bodies: unknown[]) {
  const calls: Array<{ url: string; headers: Headers; body: Record<string, unknown> | null; method: string }> = [];
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const req = input instanceof Request ? input : new Request(String(input), init);
    const text = init?.body ? String(init.body) : await req.clone().text().catch(() => "");
    calls.push({ url: req.url, headers: new Headers(init?.headers ?? req.headers), body: text ? JSON.parse(text) : null, method: init?.method ?? req.method });
    const body = bodies.length > 1 ? bodies.shift() : bodies[0];
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", "request-id": "req_1" } });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

const verdict = z.object({ verdict: z.enum(["malicious", "benign"]), confidence: z.number() });

const claudeReply = (model: string, text: string, usage: Record<string, number>) => ({
  id: "msg_1",
  type: "message",
  role: "assistant",
  model,
  content: [{ type: "text", text }],
  stop_reason: "end_turn",
  stop_sequence: null,
  usage: { input_tokens: 40, output_tokens: 12, ...usage },
});

describe("Claude in Amazon Bedrock", () => {
  it("calls Bedrock Mantle in the chosen region, signed with the access key, without the first-party fallback", async () => {
    const { calls, fetchImpl } = recorder(claudeReply("anthropic.claude-sonnet-5-5", JSON.stringify({ verdict: "malicious", confidence: 0.9 }), { cache_read_input_tokens: 1800, cache_creation_input_tokens: 0 }));
    const p = bedrockProvider({ name: "Bedrock", model: "anthropic.claude-sonnet-5-5", region: "ap-south-1", auth: { accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" }, fetch: fetchImpl });
    const r = await p.structured({ schema: verdict, schemaName: "verdict", system: "You triage alerts.", user: "Case evidence", effort: "low" });
    expect(r.data).toEqual({ verdict: "malicious", confidence: 0.9 });
    expect(r.usage).toEqual({ inputTokens: 1840, outputTokens: 12, cacheReadTokens: 1800, cacheWriteTokens: 0 });
    expect(p.kind).toBe("bedrock");
    const call = calls[0];
    expect(call.url).toMatch(/^https:\/\/bedrock-mantle\.ap-south-1\.api\.aws\/anthropic\/v1\/messages/);
    expect(call.headers.get("authorization")).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/ap-south-1\/bedrock-mantle\/aws4_request/);
    expect(call.body).not.toHaveProperty("fallbacks");
    expect(call.headers.get("anthropic-beta") ?? "").not.toContain("server-side-fallback");
    expect(call.body?.model).toBe("anthropic.claude-sonnet-5-5");
    // The instructions are a cached prefix; the evidence comes after it.
    expect(call.body?.system).toEqual([{ type: "text", text: "You triage alerts.", cache_control: { type: "ephemeral" } }]);
    expect(call.body?.messages).toEqual([{ role: "user", content: "Case evidence" }]);
  });

  it("sends a Bedrock API key as a bearer token, and tests the connection with a real request", async () => {
    const { calls, fetchImpl } = recorder(claudeReply("anthropic.claude-haiku-5-5", "OK", {}));
    const p = bedrockProvider({ name: "Bedrock", model: "anthropic.claude-haiku-5-5", region: "us-east-1", auth: { apiKey: "bedrock-key" }, fetch: fetchImpl });
    expect(await p.check()).toEqual({ ok: true, message: "Connected — anthropic.claude-haiku-5-5 in us-east-1" });
    expect(calls[0].headers.get("authorization")).toBe("Bearer bedrock-key");
    expect(calls[0].body).toMatchObject({ model: "anthropic.claude-haiku-5-5", max_tokens: 64 });
  });

  it("reads stored credentials back in either form", () => {
    expect(parseBedrockAuth(JSON.stringify({ accessKeyId: "A", secretAccessKey: "S" }))).toEqual({ accessKeyId: "A", secretAccessKey: "S" });
    expect(parseBedrockAuth(JSON.stringify({ apiKey: "K" }))).toEqual({ apiKey: "K" });
    expect(parseBedrockAuth("bare-key")).toEqual({ apiKey: "bare-key" });
    expect(parseBedrockAuth(null)).toBeNull();
  });

  it("takes Bedrock model IDs for Claude 4.7 and later only", () => {
    expect(bedrockModelProblem("anthropic.claude-sonnet-5-5")).toBeNull();
    expect(bedrockModelProblem("anthropic.claude-opus-4-7")).toBeNull();
    expect(bedrockModelProblem("claude-sonnet-5-5")).toMatch(/starts with "anthropic\."/);
    expect(bedrockModelProblem("anthropic.claude-haiku-4-5")).toMatch(/4\.7 and later/);
    expect(bedrockModelProblem("anthropic.claude-3-5-sonnet-20241022-v2:0")).not.toBeNull();
    expect(bedrockModelProblem("anthropic.claude-sonnet-4-20250514")).toMatch(/4\.7 and later/);
  });
});

describe("Claude on Anthropic's API", () => {
  it("caches the system prompt on single calls and keeps the refusal fallback", async () => {
    const { calls, fetchImpl } = recorder(claudeReply("claude-sonnet-5-5", "A summary", { cache_creation_input_tokens: 900, cache_read_input_tokens: 0 }));
    const p = anthropicProvider({ name: "Claude", model: "claude-sonnet-5-5", apiKey: "sk-ant-test", fetch: fetchImpl });
    const r = await p.text({ system: "You write client reports.", user: "Evidence", effort: "medium" });
    expect(r.data).toBe("A summary");
    expect(r.usage).toEqual({ inputTokens: 940, outputTokens: 12, cacheReadTokens: 0, cacheWriteTokens: 900 });
    expect(calls[0].url).toMatch(/^https:\/\/api\.anthropic\.com\/v1\/messages/);
    expect(calls[0].body).toMatchObject({ fallbacks: "default", system: [{ type: "text", text: "You write client reports.", cache_control: { type: "ephemeral" } }] });
    expect(calls[0].headers.get("anthropic-beta")).toContain("server-side-fallback-2026-07-01");
  });

  it("counts every input token, cached or not", () => {
    expect(usageOf({ input_tokens: 10, output_tokens: 5, cache_read_input_tokens: 100, cache_creation_input_tokens: 50 })).toEqual({ inputTokens: 160, outputTokens: 5, cacheReadTokens: 100, cacheWriteTokens: 50 });
    expect(addUsage({ inputTokens: 1, cacheReadTokens: 2 }, { inputTokens: 3, outputTokens: 4 })).toEqual({ inputTokens: 4, outputTokens: 4, cacheReadTokens: 2, cacheWriteTokens: undefined });
  });
});

describe("Azure OpenAI", () => {
  const chat = (content: string, cached = 0) => ({ model: "gpt-4o-2024-08-06", choices: [{ finish_reason: "stop", message: { content } }], usage: { prompt_tokens: 1200, completion_tokens: 30, prompt_tokens_details: { cached_tokens: cached } } });

  it("turns the portal's endpoint into the v1 API base", () => {
    expect(azureBaseUrl("https://soc-ai.openai.azure.com/")).toBe("https://soc-ai.openai.azure.com/openai/v1");
    expect(azureBaseUrl("https://soc-ai.openai.azure.com/openai")).toBe("https://soc-ai.openai.azure.com/openai/v1");
    expect(azureBaseUrl("https://soc-ai.cognitiveservices.azure.com/openai/v1/")).toBe("https://soc-ai.cognitiveservices.azure.com/openai/v1");
    expect(azureBaseUrl("https://apim.example.com/aoai/openai/v1")).toBe("https://apim.example.com/aoai/openai/v1");
  });

  it("sends the key as api-key, the deployment as the model, and reads cached prompt tokens", async () => {
    const { calls, fetchImpl } = recorder(chat(JSON.stringify({ verdict: "benign", confidence: 0.7 }), 1024));
    const p = openAiCompatibleProvider({ name: "Azure", baseUrl: "https://soc-ai.openai.azure.com", model: "triage-gpt4o", apiKey: "azure-key", isLocal: false, azure: true, fetch: fetchImpl });
    const r = await p.structured({ schema: verdict, schemaName: "verdict", system: "s", user: "u", effort: "low" });
    expect(p.kind).toBe("azure_openai");
    expect(r.data).toEqual({ verdict: "benign", confidence: 0.7 });
    expect(r.usage).toEqual({ inputTokens: 1200, outputTokens: 30, cacheReadTokens: 1024 });
    expect(calls[0].url).toBe("https://soc-ai.openai.azure.com/openai/v1/chat/completions");
    expect(calls[0].headers.get("api-key")).toBe("azure-key");
    expect(calls[0].headers.get("authorization")).toBeNull();
    expect(calls[0].body).toMatchObject({ model: "triage-gpt4o", response_format: { type: "json_schema", json_schema: { strict: false } } });
  });

  it("tests a deployment by asking it for a word, and names a missing one", async () => {
    const ok = recorder(chat("OK"));
    const p = openAiCompatibleProvider({ name: "Azure", baseUrl: "https://soc-ai.openai.azure.com", model: "triage", apiKey: "k", isLocal: false, azure: true, fetch: ok.fetchImpl });
    expect(await p.check()).toEqual({ ok: true, message: "Connected — deployment triage (gpt-4o-2024-08-06)" });
    expect(ok.calls[0].body).toMatchObject({ max_completion_tokens: 256 });
    const missing = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
    const q = openAiCompatibleProvider({ name: "Azure", baseUrl: "https://soc-ai.openai.azure.com", model: "nope", apiKey: "k", isLocal: false, azure: true, fetch: missing });
    expect(await q.check()).toEqual({ ok: false, message: "No deployment named nope at https://soc-ai.openai.azure.com/openai/v1" });
  });

  it("says why a connection failed, not just that fetch failed", () => {
    const failed = (cause: object) => Object.assign(new TypeError("fetch failed"), { cause });
    expect(reason(failed({ message: "C0DC:error:0A00045C:SSL routines:ssl3_read_bytes:tlsv13 alert certificate required:...\n" }))).toMatch(/wants a client certificate/);
    expect(reason(failed({ message: "SSL routines:ssl3_read_bytes:tlsv13 alert unknown ca" }))).toBe("the server didn't accept HELIOS's client certificate");
    expect(reason(failed({ code: "SELF_SIGNED_CERT_IN_CHAIN", message: "self-signed certificate in certificate chain" }))).toMatch(/isn't trusted .*HELIOS_AI_CA/);
    expect(reason(failed({ code: "ECONNREFUSED" }))).toBe("nothing is listening there");
    expect(reason(failed({ code: "ENOTFOUND", message: "getaddrinfo ENOTFOUND box.example" }))).toBe("the name doesn't resolve");
    expect(reason(failed({ message: "socket hang up" }))).toBe("fetch failed (socket hang up)");
    expect(reason(new Error("plain"))).toBe("plain");
  });

  it("local servers keep strict schemas and bearer keys", async () => {
    const { calls, fetchImpl } = recorder(chat(JSON.stringify({ verdict: "benign", confidence: 0.5 })));
    const p = openAiCompatibleProvider({ name: "Box", baseUrl: "https://ai-box.client.example/v1/", model: "qwen2.5:14b", apiKey: "box-key", isLocal: true, fetch: fetchImpl });
    await p.structured({ schema: verdict, schemaName: "verdict", system: "s", user: "u", effort: "low" });
    expect(calls[0].url).toBe("https://ai-box.client.example/v1/chat/completions");
    expect(calls[0].headers.get("authorization")).toBe("Bearer box-key");
    expect(calls[0].body).toMatchObject({ response_format: { json_schema: { strict: true } } });
  });
});

describe("what people type to add a provider", () => {
  const base = { name: "Ours", isLocal: false };

  it("needs a region and a valid model for Bedrock, and both halves of an access key", () => {
    const issues = (input: object) => {
      const r = providerInputSchema.safeParse({ ...base, ...input });
      return r.success ? [] : r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`);
    };
    expect(issues({ kind: "bedrock", model: "anthropic.claude-sonnet-5-5", region: "ap-south-1", apiKey: "k" })).toEqual([]);
    expect(issues({ kind: "bedrock", model: "anthropic.claude-sonnet-5-5", region: "mumbai" })).toEqual(["region: Bedrock needs the AWS region it calls, such as ap-south-1"]);
    expect(issues({ kind: "bedrock", model: "claude-sonnet-5-5", region: "ap-south-1" })[0]).toMatch(/^model: /);
    expect(issues({ kind: "bedrock", model: "anthropic.claude-sonnet-5-5", region: "ap-south-1", awsAccessKeyId: "AKIA" })).toEqual(["awsSecretAccessKey: An access key needs both its ID and its secret"]);
    expect(issues({ kind: "azure_openai", model: "gpt-4o", baseUrl: "http://soc-ai.openai.azure.com" })).toEqual(["baseUrl: An Azure OpenAI endpoint starts with https://"]);
    expect(issues({ kind: "openai_compatible", model: "m" })[0]).toMatch(/needs its base URL/);
  });

  it("stores Bedrock credentials as JSON and only the columns each kind uses", () => {
    const keys = providerInputSchema.parse({ ...base, kind: "bedrock", model: "anthropic.claude-opus-5-5", region: "ap-south-1", awsAccessKeyId: "AKIA", awsSecretAccessKey: "S", baseUrl: "https://ignored.example" });
    expect(JSON.parse(providerSecret(keys)!)).toEqual({ accessKeyId: "AKIA", secretAccessKey: "S" });
    expect(providerColumns(keys)).toEqual({ name: "Ours", kind: "bedrock", baseUrl: null, model: "anthropic.claude-opus-5-5", isLocal: false, region: "ap-south-1" });
    const azure = providerInputSchema.parse({ ...base, kind: "azure_openai", model: "gpt-4o", baseUrl: "https://x.openai.azure.com", apiKey: "k", isLocal: true });
    expect(providerSecret(azure)).toBe("k");
    expect(providerColumns(azure)).toMatchObject({ baseUrl: "https://x.openai.azure.com", isLocal: false });
    expect(providerSecret(providerInputSchema.parse({ ...base, kind: "bedrock", model: "anthropic.claude-opus-5-5", region: "ap-south-1" }))).toBeUndefined();
  });

  it("keeps a client's own endpoint to public https addresses", async () => {
    const guarded = clientEndpointFetch()!;
    await expect(guarded("http://ai-box.client.example/v1/models")).rejects.toThrow("Only https:// addresses");
    await expect(guarded("https://169.254.169.254/latest/meta-data")).rejects.toThrow("private or internal address");
    await expect(guarded("https://10.0.0.5/v1/models")).rejects.toThrow("private or internal address");
    process.env.HELIOS_ALLOW_PRIVATE_CLIENT_AI = "1";
    try {
      expect(clientEndpointFetch()).toBeUndefined();
    } finally {
      delete process.env.HELIOS_ALLOW_PRIVATE_CLIENT_AI;
    }
  });
});

describe("regions", () => {
  it("matches a cloud region to the jurisdiction a rule names", () => {
    expect(regionSatisfies("ap-south-1", "india")).toBe(true);
    expect(regionSatisfies("centralindia", "India")).toBe(true);
    expect(regionSatisfies("asia-south2", "in")).toBe(true);
    expect(regionSatisfies("us-east-1", "india")).toBe(false);
    expect(regionSatisfies("eu-central-1", "eu")).toBe(true);
    expect(regionSatisfies("swedencentral", "europe")).toBe(true);
    expect(regionSatisfies("eastus2", "us")).toBe(true);
    expect(regionSatisfies("ap-south-1", "ap-south-1")).toBe(true);
    expect(regionSatisfies(null, "india")).toBe(false);
    expect(inIndia("jioindiawest")).toBe(true);
  });

  it("lets a Bedrock provider in Mumbai run an India-locked client's evidence", () => {
    const rules = { residency: "region" as const, regions: ["india"], allowedProviders: [] };
    const c = (region: string | null): Candidate => ({ source: "platform", id: "p1", name: "Bedrock", model: "anthropic.claude-sonnet-5-5", isLocal: false, region, tenantId: null });
    expect(whyNot(c("ap-south-1"), "t1", rules)).toBeNull();
    expect(whyNot(c("us-east-1"), "t1", rules)).toBe("runs in us-east-1; the client requires india");
  });
});

describe("what AI runs cost with a prompt cache", () => {
  const price = { inputPer: 3, outputPer: 15 };

  it("prices cache reads at a tenth and cache writes at 1.25× the input price", () => {
    expect(runCost({ model: "m", inputTokens: 1_000_000, outputTokens: 0 }, price)).toBeCloseTo(3);
    expect(runCost({ model: "m", inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 1_000_000 }, price)).toBeCloseTo(0.3);
    expect(runCost({ model: "m", inputTokens: 1_000_000, outputTokens: 100_000, cacheWriteTokens: 500_000 }, price)).toBeCloseTo(1.5 + 1.875 + 1.5);
  });

  it("prices Bedrock model IDs as the same model", () => {
    expect(priceKey("anthropic.claude-sonnet-5-5")).toBe("claude-sonnet-5-5");
    expect(priceKey("global.anthropic.claude-opus-5-5")).toBe("claude-opus-5-5");
    expect(priceKey("claude-haiku-5-5")).toBe("claude-haiku-5-5");
    expect(priceKey("gpt-4o")).toBe("gpt-4o");
  });
});
