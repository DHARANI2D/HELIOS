import Anthropic from "@anthropic-ai/sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import type { z } from "zod";

import { AgentRefusalError, type LlmProvider, type LlmResult, type StructuredRequest, type TextRequest } from "@/lib/ai/provider";

// Claude via the official SDK, with structured outputs. Security telemetry
// is attack activity by definition, so requests opt into server-side refusal
// fallback: a safety-classifier decline is re-run on Anthropic's recommended
// fallback model inside the same call instead of failing the stage. Haiku has
// no server-side fallback, so it goes without.

const clients = new Map<string, Anthropic>();

function clientFor(apiKey?: string) {
  const cacheKey = apiKey ?? "env";
  let client = clients.get(cacheKey);
  if (!client) {
    client = apiKey ? new Anthropic({ apiKey }) : new Anthropic();
    clients.set(cacheKey, client);
  }
  return client;
}

function supportsFallback(model: string) {
  return !model.startsWith("claude-haiku");
}

export function anthropicProvider(options: { name: string; model: string; apiKey?: string }): LlmProvider {
  const { name, model, apiKey } = options;

  function base() {
    return {
      model,
      max_tokens: 16000,
      ...(supportsFallback(model)
        ? { betas: ["server-side-fallback-2026-07-01"] as Anthropic.Beta.AnthropicBeta[], fallbacks: "default" as const }
        : {}),
    };
  }

  return {
    name,
    kind: "anthropic",
    model,
    isLocal: false,

    async structured<S extends z.ZodType>({ schema, system, user, effort }: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>> {
      const response = await clientFor(apiKey).beta.messages.parse({
        ...base(),
        output_config: { effort, format: betaZodOutputFormat(schema) },
        system,
        messages: [{ role: "user", content: user }],
      });
      if (response.stop_reason === "refusal") {
        throw new AgentRefusalError(`Model declined the request (${response.stop_details?.category ?? "unspecified"})`);
      }
      if (!response.parsed_output) throw new Error(`No structured output (stop_reason: ${response.stop_reason})`);
      return {
        data: response.parsed_output as z.infer<S>,
        model: response.model,
        usage: { inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens },
      };
    },

    async text({ system, user, effort }: TextRequest): Promise<LlmResult<string>> {
      const response = await clientFor(apiKey).beta.messages.create({
        ...base(),
        output_config: { effort },
        system,
        messages: [{ role: "user", content: user }],
      });
      if (response.stop_reason === "refusal") {
        throw new AgentRefusalError(`Model declined the request (${response.stop_details?.category ?? "unspecified"})`);
      }
      const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n").trim();
      if (!text) throw new Error(`Empty response (stop_reason: ${response.stop_reason})`);
      return { data: text, model: response.model, usage: { inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens } };
    },

    // Model metadata lookup: proves the key and model id without spending tokens.
    async check() {
      try {
        const info = await clientFor(apiKey).models.retrieve(model);
        return { ok: true, message: `Connected — ${info.display_name ?? info.id}` };
      } catch (err) {
        if (err instanceof Anthropic.AuthenticationError) return { ok: false, message: "API key rejected" };
        if (err instanceof Anthropic.NotFoundError) return { ok: false, message: `Model ${model} not available to this key` };
        if (err instanceof Anthropic.APIError) return { ok: false, message: `API error ${err.status}: ${err.message}` };
        return { ok: false, message: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}
