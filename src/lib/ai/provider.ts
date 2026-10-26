import type { z } from "zod";

import type { ProviderKind } from "@/lib/ai/catalog";

// The seam between HELIOS's agents and whatever model runs them: Claude
// online today, a local OpenAI-compatible server (Ollama, LM Studio, vLLM)
// for offline deployments. Agents only ever ask for schema-validated
// structured output or plain text; a null provider means the built-in
// deterministic engine handles that stage instead.

export type Effort = "low" | "medium" | "high";

export interface LlmUsage {
  inputTokens?: number;
  outputTokens?: number;
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
