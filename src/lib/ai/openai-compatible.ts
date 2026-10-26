import { z } from "zod";

import type { AgentRequest, AgentSession, AgentStep, AgentToolResult, LlmProvider, LlmResult, StructuredRequest, TextRequest } from "@/lib/ai/provider";

// Local / self-hosted models behind the OpenAI-compatible chat completions
// API that Ollama, LM Studio, vLLM and llama.cpp's server all expose — the
// offline option for clients whose telemetry must not leave their network.
// Structured output uses response_format json_schema; local models are less
// reliable at it than hosted ones, so the reply is validated with Zod and
// re-asked once with the validation errors before giving up.

const TIMEOUT_MS = Number(process.env.AI_LOCAL_TIMEOUT_MS ?? 180_000);

interface ToolCall {
  id: string;
  type: "function";
  function: { name: string; arguments: string };
}

interface ChatResponse {
  model?: string;
  choices?: Array<{ finish_reason?: string; message?: { content?: string | null; tool_calls?: ToolCall[] } }>;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
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

export function openAiCompatibleProvider(options: { name: string; baseUrl: string; model: string; apiKey?: string; isLocal: boolean }): LlmProvider {
  const { name, model, apiKey, isLocal } = options;
  const baseUrl = options.baseUrl.replace(/\/+$/, "");

  async function chat(messages: Message[], responseFormat?: unknown, tools?: unknown[]): Promise<ChatResponse> {
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}) },
      body: JSON.stringify({ model, messages, stream: false, ...(responseFormat ? { response_format: responseFormat } : {}), ...(tools ? { tools, tool_choice: "auto" } : {}) }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`${name} returned HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return (await res.json()) as ChatResponse;
  }

  const usageOf = (r: ChatResponse) => ({ inputTokens: r.usage?.prompt_tokens, outputTokens: r.usage?.completion_tokens });

  return {
    name,
    kind: "openai_compatible",
    model,
    isLocal,

    async structured<S extends z.ZodType>({ schema, schemaName, system, user }: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>> {
      const { $schema: _ignored, ...jsonSchema } = z.toJSONSchema(schema) as Record<string, unknown>;
      const format = { type: "json_schema", json_schema: { name: schemaName, schema: jsonSchema, strict: true } };
      const messages: Message[] = [
        { role: "system", content: `${system}\n\nRespond with a single JSON object that matches the provided schema. No prose.` },
        { role: "user", content: user },
      ];
      let inputTokens = 0;
      let outputTokens = 0;
      let lastError = "";
      for (let attempt = 0; attempt < 2; attempt++) {
        const response = await chat(messages, format);
        const usage = usageOf(response);
        inputTokens += usage.inputTokens ?? 0;
        outputTokens += usage.outputTokens ?? 0;
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
          return { data: result.data as z.infer<S>, model: response.model ?? model, usage: { inputTokens, outputTokens } };
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
      try {
        const res = await fetch(`${baseUrl}/models`, {
          headers: apiKey ? { authorization: `Bearer ${apiKey}` } : {},
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
