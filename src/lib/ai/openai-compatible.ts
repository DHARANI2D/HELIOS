import { z } from "zod";

import { addUsage, type AgentRequest, type AgentSession, type AgentStep, type AgentToolResult, type LlmProvider, type LlmResult, type LlmUsage, type StructuredRequest, type TextRequest } from "@/lib/ai/provider";

// Local / self-hosted models behind the OpenAI-compatible chat completions
// API that Ollama, LM Studio, vLLM and llama.cpp's server all expose — the
// offline option for clients whose telemetry must not leave their network.
// Structured output uses response_format json_schema; local models are less
// reliable at it than hosted ones, so the reply is validated with Zod and
// re-asked once with the validation errors before giving up.
//
// Azure OpenAI is the same API (its v1 endpoint, /openai/v1) with the key
// in an api-key header and the deployment's name as the model. It enforces
// strict JSON schemas only in OpenAI's subset (every property required), so
// there the schema guides the reply and Zod checks it, as with local models.

const TIMEOUT_MS = Number(process.env.AI_LOCAL_TIMEOUT_MS ?? 180_000);

interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

interface ChatResponse {
  model?: string;
  choices?: Array<{ finish_reason?: string; message?: { content?: string | null; tool_calls?: ToolCall[] } }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } };
}

type Message =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string | null; tool_calls?: ToolCall[] }
  | { role: "tool"; tool_call_id: string; content: string };

// Reasoning models (qwen3, deepseek-r1) prefix <think> blocks; some models
// wrap JSON in code fences despite the schema.
export function extractJson(content: string): unknown {
  const cleaned = content
    .replace(/<think>[\s\S]*?<\/think>/g, "")
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "");
  const start = cleaned.search(/[{[]/);
  return JSON.parse(start > 0 ? cleaned.slice(start) : cleaned);
}

// An Azure OpenAI resource's endpoint as people copy it from the portal
// (https://NAME.openai.azure.com/) becomes its v1 API base.
export function azureBaseUrl(endpoint: string) {
  const url = endpoint.trim().replace(/\/+$/, "");
  if (/\/openai\/v1$/i.test(url)) return url;
  if (/\/openai$/i.test(url)) return `${url}/v1`;
  return new URL(url).pathname === "/" ? `${url}/openai/v1` : url;
}

interface Options {
  name: string;
  baseUrl: string;
  model: string;
  apiKey?: string;
  isLocal: boolean;
  // Azure OpenAI: the key goes in an api-key header, the base URL is the
  // resource's endpoint.
  azure?: boolean;
  // Where requests go out through (lib/ai/resolve guards client-entered
  // addresses).
  fetch?: typeof fetch;
}

export function openAiCompatibleProvider(options: Options): LlmProvider {
  const { name, model, apiKey, isLocal, azure } = options;
  const baseUrl = azure ? azureBaseUrl(options.baseUrl) : options.baseUrl.replace(/\/+$/, "");
  const doFetch = options.fetch ?? fetch;
  const auth: Record<string, string> = apiKey ? (azure ? { "api-key": apiKey } : { authorization: `Bearer ${apiKey}` }) : {};

  async function chat(messages: Message[], responseFormat?: unknown, tools?: unknown[], extra: Record<string, unknown> = {}): Promise<ChatResponse> {
    const res = await doFetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", ...auth },
      body: JSON.stringify({ model, messages, stream: false, ...(responseFormat ? { response_format: responseFormat } : {}), ...(tools ? { tools, tool_choice: "auto" } : {}), ...extra }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`${name} returned HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return (await res.json()) as ChatResponse;
  }

  // OpenAI-style servers (Azure among them) cache long prompts on their own
  // and report how much of the prompt came from the cache.
  const usageOf = (r: ChatResponse): LlmUsage => ({
    inputTokens: r.usage?.prompt_tokens,
    outputTokens: r.usage?.completion_tokens,
    ...(r.usage?.prompt_tokens_details?.cached_tokens ? { cacheReadTokens: r.usage.prompt_tokens_details.cached_tokens } : {}),
  });

  return {
    name,
    kind: azure ? "azure_openai" : "openai_compatible",
    model,
    isLocal,

    async structured<S extends z.ZodType>({ schema, schemaName, system, user }: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>> {
      const { $schema: _ignored, ...jsonSchema } = z.toJSONSchema(schema) as Record<string, unknown>;
      const format = { type: "json_schema", json_schema: { name: schemaName, schema: jsonSchema, strict: !azure } };
      const messages: Message[] = [
        { role: "system", content: `${system}\n\nRespond with a single JSON object that matches the provided schema. No prose.` },
        { role: "user", content: user },
      ];
      let usage: LlmUsage = {};
      let lastError = "";
      for (let attempt = 0; attempt < 2; attempt++) {
        const response = await chat(messages, format);
        usage = addUsage(usage, usageOf(response));
        const content = response.choices?.[0]?.message?.content ?? "";
        let parsed: unknown;
        try {
          parsed = extractJson(content);
        } catch {
          lastError = "reply was not valid JSON";
          messages.push({ role: "assistant", content }, { role: "user", content: "That was not valid JSON. Reply again with only the JSON object." });
          continue;
        }
        const result = schema.safeParse(parsed);
        if (result.success) {
          return { data: result.data as z.infer<S>, model: response.model ?? model, usage };
        }
        lastError = result.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
        messages.push({ role: "assistant", content }, { role: "user", content: `The JSON did not match the schema (${lastError}). Reply again with a corrected JSON object only.` });
      }
      throw new Error(`${name} did not produce valid structured output: ${lastError}`);
    },

    async text({ system, user }: TextRequest): Promise<LlmResult<string>> {
      const response = await chat([
        { role: "system", content: system },
        { role: "user", content: user },
      ]);
      const text = (response.choices?.[0]?.message?.content ?? "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
      if (!text) throw new Error(`${name} returned an empty response`);
      return { data: text, model: response.model ?? model, usage: usageOf(response) };
    },

    // Function calling, as Ollama, vLLM, LM Studio and llama.cpp's server
    // expose it (support depends on the model). Arguments arrive as a JSON
    // string; one that doesn't parse goes back to the model as an error.
    agent({ system, user, tools }: AgentRequest): AgentSession {
      const messages: Message[] = [
        { role: "system", content: system },
        { role: "user", content: user },
      ];
      const fns = [...tools].sort((a, b) => a.name.localeCompare(b.name)).map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.inputSchema } }));
      return {
        async step(results?: AgentToolResult[], note?: string): Promise<AgentStep> {
          for (const r of results ?? []) messages.push({ role: "tool", tool_call_id: r.id, content: r.isError ? `Error: ${r.content}` : r.content });
          if (note) messages.push({ role: "user", content: note });
          const response = await chat(messages, undefined, fns);
          const choice = response.choices?.[0];
          const message = choice?.message ?? {};
          const toolCalls = message.tool_calls ?? [];
          messages.push({ role: "assistant", content: message.content ?? null, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) });
          const calls = toolCalls.map((c) => {
            let input: unknown;
            try {
              input = JSON.parse(c.function.arguments || "{}");
            } catch {
              input = { __unparsed: c.function.arguments };
            }
            return { id: c.id, name: c.function.name, input };
          });
          const text = (message.content ?? "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
          const stop = calls.length ? "tool_use" : choice?.finish_reason === "length" ? "max_tokens" : "end_turn";
          return { calls, text, stop, model: response.model ?? model, usage: usageOf(response) };
        },
      };
    },

    async check() {
      if (azure) {
        // Azure's model list names base models, not deployments: ask the
        // deployment for a word instead.
        try {
          const r = await chat([{ role: "user", content: "Reply with OK." }], undefined, undefined, { max_completion_tokens: 256 });
          return { ok: true, message: `Connected — deployment ${model}${r.model ? ` (${r.model})` : ""}` };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (/HTTP 401/.test(msg)) return { ok: false, message: "API key rejected" };
          if (/HTTP 404/.test(msg)) return { ok: false, message: `No deployment named ${model} at ${baseUrl}` };
          return { ok: false, message: msg };
        }
      }
      try {
        const res = await doFetch(`${baseUrl}/models`, {
          headers: auth,
          signal: AbortSignal.timeout(8_000),
        });
        if (!res.ok) return { ok: false, message: `HTTP ${res.status} from ${baseUrl}/models` };
        const body = (await res.json()) as { data?: Array<{ id: string }> };
        const ids = body.data?.map((m) => m.id) ?? [];
        if (ids.length && !ids.includes(model)) {
          return { ok: false, message: `Server is up but ${model} isn't loaded (has: ${ids.slice(0, 5).join(", ")})` };
        }
        return { ok: true, message: `Connected — ${model} available` };
      } catch (err) {
        return { ok: false, message: `Can't reach ${baseUrl}: ${err instanceof Error ? err.message : String(err)}` };
      }
    },
  };
}
