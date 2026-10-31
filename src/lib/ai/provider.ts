import type { z } from "zod";

import type { ProviderKind } from "@/lib/ai/catalog";

// The seam between HELIOS's agents and whatever model runs them: Claude
// (Anthropic's API, or Claude in Amazon Bedrock), Azure OpenAI, or a local
// OpenAI-compatible server (Ollama, LM Studio, vLLM) for offline
// deployments. Agents only ever ask for schema-validated
// structured output or plain text; a null provider means the built-in
// deterministic engine handles that stage instead.

export type Effort = "low" | "medium" | "high";

// inputTokens is every input token the model read, cached or not; the
// cache counts say how many of them were read from or written to the
// prompt cache (they cost less and more than the rest, lib/pricing).
export interface LlmUsage {
  inputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

// Adds one call's usage to a running total.
export function addUsage(total: LlmUsage, add: LlmUsage): LlmUsage {
  const sum = (a?: number, b?: number) => (a == null && b == null ? undefined : (a ?? 0) + (b ?? 0));
  return { inputTokens: sum(total.inputTokens, add.inputTokens), outputTokens: sum(total.outputTokens, add.outputTokens), cacheReadTokens: sum(total.cacheReadTokens, add.cacheReadTokens), cacheWriteTokens: sum(total.cacheWriteTokens, add.cacheWriteTokens) };
}

// The AiRun columns for a usage.
export function usageColumns(u: LlmUsage) {
  return { inputTokens: u.inputTokens ?? null, outputTokens: u.outputTokens ?? null, cacheReadTokens: u.cacheReadTokens ?? null, cacheWriteTokens: u.cacheWriteTokens ?? null };
}

export interface LlmResult<T> {
  data: T;
  // The model that actually answered (a refusal fallback can change it).
  model: string;
  usage: LlmUsage;
}

export interface StructuredRequest<S extends z.ZodType> {
  schema: S;
  schemaName: string;
  system: string;
  user: string;
  effort: Effort;
}

export interface TextRequest {
  system: string;
  user: string;
  effort: Effort;
}

// An agent session: the model calls tools the caller defines, the caller
// runs them and hands the results back, turn by turn. The transcript stays
// inside the session in the provider's own form (thinking and tool blocks
// passed back unchanged, append-only), so callers never rebuild it.
export interface AgentTool {
  name: string;
  description: string;
  // JSON Schema for the input; objects close with additionalProperties: false.
  inputSchema: Record<string, unknown>;
}

export interface AgentCall {
  id: string;
  name: string;
  input: unknown;
}

export interface AgentToolResult {
  id: string;
  content: string;
  isError?: boolean;
}

export interface AgentStep {
  calls: AgentCall[];
  text: string;
  stop: "tool_use" | "end_turn" | "max_tokens" | "pause_turn";
  model: string;
  usage: LlmUsage;
}

export interface AgentRequest {
  system: string;
  user: string;
  tools: AgentTool[];
  effort: Effort;
}

export interface AgentSession {
  // Results for the previous step's calls (all of them, in one turn), and
  // optionally a note to the model after them.
  step(results?: AgentToolResult[], note?: string): Promise<AgentStep>;
}

export interface LlmProvider {
  name: string;
  kind: ProviderKind;
  model: string;
  isLocal: boolean;
  structured<S extends z.ZodType>(request: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>>;
  text(request: TextRequest): Promise<LlmResult<string>>;
  // Tool use; absent where the provider can't run tools.
  agent?(request: AgentRequest): AgentSession;
  check(): Promise<{ ok: boolean; message: string }>;
}

// The model declined (safety classifier) — callers fall back to the
// deterministic engine for that stage rather than failing the case.
export class AgentRefusalError extends Error {}
