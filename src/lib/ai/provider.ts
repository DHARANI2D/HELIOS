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

export interface LlmProvider {
  name: string;
  kind: ProviderKind;
  model: string;
  isLocal: boolean;
  structured<S extends z.ZodType>(request: StructuredRequest<S>): Promise<LlmResult<z.infer<S>>>;
  text(request: TextRequest): Promise<LlmResult<string>>;
  check(): Promise<{ ok: boolean; message: string }>;
}

// The model declined (safety classifier) — callers fall back to the
// deterministic engine for that stage rather than failing the case.
export class AgentRefusalError extends Error {}
