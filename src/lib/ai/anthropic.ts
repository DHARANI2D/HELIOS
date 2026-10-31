import { createHash } from "node:crypto";

import Anthropic from "@anthropic-ai/sdk";
import { AnthropicBedrockMantle } from "@anthropic-ai/bedrock-sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import type { z } from "zod";

import { AgentRefusalError, type AgentRequest, type AgentSession, type AgentStep, type AgentToolResult, type LlmProvider, type LlmResult, type LlmUsage, type StructuredRequest, type TextRequest } from "@/lib/ai/provider";

// Claude through the official SDKs: Anthropic's API, or Claude in Amazon
// Bedrock (the Bedrock Mantle endpoint, which serves the same Messages API
// in the client's own AWS account and region). Structured outputs on both.
//
// On Anthropic's API, security telemetry being attack activity by
// definition, requests opt into server-side refusal fallback: a
// safety-classifier decline is re-run on Anthropic's recommended fallback
// model inside the same call instead of failing the stage. Haiku has no
// server-side fallback, and Bedrock doesn't offer it, so those go without
// (a refusal there falls back to the built-in engine for that stage).
//
// Prompt caching: every request marks the end of its system prompt (tools
// render before it, so they're cached too), so the agent's instructions are
// read from cache on the next case within a few minutes. The case evidence
// comes after the mark and is never part of the cached prefix.

// What the providers below need from a client; both SDK clients have it.
interface ClaudeClient {
  beta: { messages: Anthropic["beta"]["messages"] };
}

const clients = new Map<string, ClaudeClient>();

function cached(key: string, make: () => ClaudeClient) {
  let client = clients.get(key);
  if (!client) {
    client = make();
    clients.set(key, client);
  }
  return client;
}

const digest = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");

function anthropicClient(apiKey?: string, fetchImpl?: typeof fetch): Anthropic {
  const make = () => new Anthropic({ ...(apiKey ? { apiKey } : {}), ...(fetchImpl ? { fetch: fetchImpl } : {}) });
  // A test's fetch gets its own client; real ones are shared per key.
  return (fetchImpl ? make() : cached(`anthropic:${apiKey ? digest(apiKey) : "env"}`, make)) as Anthropic;
}

function supportsFallback(model: string) {
  return !model.startsWith("claude-haiku");
}

export function usageOf(u: { input_tokens: number; output_tokens: number; cache_creation_input_tokens?: number | null; cache_read_input_tokens?: number | null }): LlmUsage {
  const read = u.cache_read_input_tokens ?? 0;
  const write = u.cache_creation_input_tokens ?? 0;
  // input_tokens counts only what came after the last cache mark.
  return { inputTokens: u.input_tokens + read + write, outputTokens: u.output_tokens, cacheReadTokens: read, cacheWriteTokens: write };
}

const cachedSystem = (system: string) => [{ type: "text" as const, text: system, cache_control: { type: "ephemeral" as const } }];

function refused(response: { stop_reason: string | null; stop_details?: { category?: string | null } | null }) {
  if (response.stop_reason === "refusal") throw new AgentRefusalError(`Model declined the request (${response.stop_details?.category ?? "unspecified"})`);
}

interface ClaudeSetup {
  name: string;
  kind: "anthropic" | "bedrock";
  model: string;
  client: () => ClaudeClient;
  fallbacks: boolean;
  check: () => Promise<{ ok: boolean; message: string }>;
}

function claudeProvider({ name, kind, model, client, fallbacks, check }: ClaudeSetup): LlmProvider {
  function base() {
    return {
      model,
      max_tokens: 16000,
      ...(fallbacks ? { betas: ["server-side-fallback-2026-07-01"] as Anthropic.Beta.AnthropicBeta[], fallbacks: "default" as const } : {}),
    };
  }

  return {
    name,
    kind,
    model,
    isLocal: false,

    async structured<S extends z.ZodType>({ schema, system, user, effort }: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>> {
      const response = await client().beta.messages.parse({
        ...base(),
        output_config: { effort, format: betaZodOutputFormat(schema) },
        system: cachedSystem(system),
        messages: [{ role: "user", content: user }],
      });
      refused(response);
      if (!response.parsed_output) throw new Error(`No structured output (stop_reason: ${response.stop_reason})`);
      return { data: response.parsed_output as z.infer<S>, model: response.model, usage: usageOf(response.usage) };
    },

    async text({ system, user, effort }: TextRequest): Promise<LlmResult<string>> {
      const response = await client().beta.messages.create({
        ...base(),
        output_config: { effort },
        system: cachedSystem(system),
        messages: [{ role: "user", content: user }],
      });
      refused(response);
      const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n").trim();
      if (!text) throw new Error(`Empty response (stop_reason: ${response.stop_reason})`);
      return { data: text, model: response.model, usage: usageOf(response.usage) };
    },

    // Tool use, one manual turn at a time (the caller runs the tools and
    // decides when to stop). The transcript is append-only: each response's
    // content goes back unchanged, thinking blocks included. Caching: a
    // breakpoint on the system prompt (tools render before it, so both are
    // cached) plus automatic caching of the growing transcript. Tools are
    // sorted and never change within a session, so the prefix stays stable.
    agent({ system, user, tools, effort }: AgentRequest): AgentSession {
      const messages: Anthropic.Beta.BetaMessageParam[] = [{ role: "user", content: user }];
      const toolDefs: Anthropic.Beta.BetaTool[] = [...tools]
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((t) => ({ name: t.name, description: t.description, input_schema: t.inputSchema as Anthropic.Beta.BetaTool.InputSchema, strict: true }));
      return {
        async step(results?: AgentToolResult[], note?: string): Promise<AgentStep> {
          const content: Anthropic.Beta.BetaContentBlockParam[] = [
            ...(results ?? []).map((r): Anthropic.Beta.BetaToolResultBlockParam => ({ type: "tool_result", tool_use_id: r.id, content: r.content, ...(r.isError ? { is_error: true } : {}) })),
            ...(note ? [{ type: "text" as const, text: note }] : []),
          ];
          if (content.length) messages.push({ role: "user", content });
          const response = await client().beta.messages.create({
            ...base(),
            output_config: { effort },
            system: cachedSystem(system),
            cache_control: { type: "ephemeral" },
            tools: toolDefs,
            messages,
          });
          refused(response);
          messages.push({ role: "assistant", content: response.content });
          const calls = response.content.flatMap((b) => (b.type === "tool_use" ? [{ id: b.id, name: b.name, input: b.input }] : []));
          const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n").trim();
          const stop = response.stop_reason === "tool_use" || response.stop_reason === "max_tokens" || response.stop_reason === "pause_turn" ? response.stop_reason : "end_turn";
          return { calls, text, stop, model: response.model, usage: usageOf(response.usage) };
        },
      };
    },

    check,
  };
}

function apiProblem(err: unknown, model: string) {
  if (err instanceof Anthropic.AuthenticationError) return "Credentials rejected";
  if (err instanceof Anthropic.PermissionDeniedError) return `Not allowed to use ${model} (HTTP 403): check the key's permissions or the model access`;
  if (err instanceof Anthropic.NotFoundError) return `Model ${model} not available here`;
  if (err instanceof Anthropic.APIError) return `API error ${err.status}: ${err.message}`;
  return err instanceof Error ? err.message : String(err);
}

export function anthropicProvider(options: { name: string; model: string; apiKey?: string; fetch?: typeof fetch }): LlmProvider {
  const { name, model, apiKey } = options;
  const client = () => anthropicClient(apiKey, options.fetch);
  return claudeProvider({
    name,
    kind: "anthropic",
    model,
    client,
    fallbacks: supportsFallback(model),
    // Model metadata lookup: proves the key and model id without spending tokens.
    async check() {
      try {
        const info = await client().models.retrieve(model);
        return { ok: true, message: `Connected — ${info.display_name ?? info.id}` };
      } catch (err) {
        return { ok: false, message: err instanceof Anthropic.AuthenticationError ? "API key rejected" : apiProblem(err, model) };
      }
    },
  });
}

// Bedrock credentials: a Bedrock API key, an access key pair, or nothing,
// which means the server's own AWS identity (its IAM role, or the AWS_*
// environment) — allowed for platform providers only (lib/ai/resolve).
export type BedrockAuth = { apiKey: string } | { accessKeyId: string; secretAccessKey: string; sessionToken?: string } | null;

// Stored sealed as JSON; a bare string is an API key.
export function parseBedrockAuth(secret: string | null | undefined): BedrockAuth {
  if (!secret) return null;
  try {
    const v = JSON.parse(secret) as Record<string, unknown>;
    if (typeof v.accessKeyId === "string" && typeof v.secretAccessKey === "string") {
      return { accessKeyId: v.accessKeyId, secretAccessKey: v.secretAccessKey, ...(typeof v.sessionToken === "string" && v.sessionToken ? { sessionToken: v.sessionToken } : {}) };
    }
    if (typeof v.apiKey === "string") return { apiKey: v.apiKey };
  } catch {
    // not JSON: a bare API key
  }
  return { apiKey: secret };
}

export function bedrockProvider(options: { name: string; model: string; region: string; auth: BedrockAuth; fetch?: typeof fetch }): LlmProvider {
  const { name, model, region, auth } = options;
  const make = () =>
    new AnthropicBedrockMantle({
      awsRegion: region,
      ...(auth && "apiKey" in auth ? { apiKey: auth.apiKey } : {}),
      ...(auth && "accessKeyId" in auth ? { apiKey: null, awsAccessKey: auth.accessKeyId, awsSecretAccessKey: auth.secretAccessKey, awsSessionToken: auth.sessionToken ?? null } : {}),
      ...(options.fetch ? { fetch: options.fetch } : {}),
    }) as unknown as ClaudeClient;
  const client = () => (options.fetch ? make() : cached(`bedrock:${region}:${digest(auth)}`, make));
  return claudeProvider({
    name,
    kind: "bedrock",
    model,
    client,
    fallbacks: false,
    // Bedrock has no models API: the smallest real request instead.
    async check() {
      try {
        const r = await client().beta.messages.create({ model, max_tokens: 64, messages: [{ role: "user", content: "Reply with OK." }] });
        return { ok: true, message: `Connected — ${r.model} in ${region}` };
      } catch (err) {
        return { ok: false, message: apiProblem(err, model) };
      }
    },
  });
}
