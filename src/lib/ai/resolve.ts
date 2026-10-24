import type { AiAgentProfile, AiProvider } from "@prisma/client";

import { db } from "@/lib/db";
import { unseal } from "@/lib/secrets";
import { AGENT_TYPES, type AgentKey } from "@/lib/ai/catalog";
import type { Effort, LlmProvider } from "@/lib/ai/provider";
import { anthropicProvider } from "@/lib/ai/anthropic";
import { openAiCompatibleProvider } from "@/lib/ai/openai-compatible";

// Which model runs which agent. Order of precedence:
//   HELIOS_AI_ENGINE=builtin (or INVESTIGATIONS_ENGINE=heuristic for the
//   investigation swarm)  → deterministic engine everywhere
//   the agent profile's provider → the platform default provider →
//   an ANTHROPIC_API_KEY in the environment → deterministic engine.

export type AgentProfileView = Pick<
  AiAgentProfile,
  "key" | "name" | "enabled" | "autonomy" | "allowedActions" | "minConfidence" | "instructions" | "model" | "providerId"
> & { effort: Effort };

function defaultProfile(key: AgentKey): AgentProfileView {
  const type = AGENT_TYPES[key];
  return {
    key,
    name: type.name,
    enabled: true,
    autonomy: type.defaultAutonomy,
    allowedActions: type.defaultActions,
    minConfidence: type.defaultMinConfidence,
    instructions: null,
    model: null,
    providerId: null,
    effort: "medium",
  };
}

export async function loadProfile(key: AgentKey): Promise<AgentProfileView> {
  const row = await db.aiAgentProfile.findUnique({ where: { key } });
  if (!row) return defaultProfile(key);
  const effort = (["low", "medium", "high"].includes(row.effort) ? row.effort : "medium") as Effort;
  return { ...row, effort };
}

export function envClaudeAvailable() {
  return !!(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}

function forcedBuiltin(key: AgentKey) {
  if (process.env.HELIOS_AI_ENGINE === "builtin") return true;
  if (key === "investigation" && process.env.INVESTIGATIONS_ENGINE === "heuristic") return true;
  return false;
}

export function providerFromRow(row: AiProvider, modelOverride?: string | null): LlmProvider {
  const model = modelOverride || row.model;
  const apiKey = row.apiKeyCipher ? unseal(row.apiKeyCipher) : undefined;
  if (row.kind === "anthropic") return anthropicProvider({ name: row.name, model, apiKey });
  if (!row.baseUrl) throw new Error(`Provider ${row.name} has no base URL`);
  return openAiCompatibleProvider({ name: row.name, baseUrl: row.baseUrl, model, apiKey, isLocal: row.isLocal });
}

export async function resolveProvider(key: AgentKey, profile?: AgentProfileView): Promise<LlmProvider | null> {
  if (forcedBuiltin(key)) return null;
  const p = profile ?? (await loadProfile(key));

  const row = p.providerId
    ? await db.aiProvider.findFirst({ where: { id: p.providerId, enabled: true } })
    : await db.aiProvider.findFirst({ where: { isDefault: true, enabled: true } });
  if (row) return providerFromRow(row, p.model);

  if (envClaudeAvailable() || (key === "investigation" && process.env.INVESTIGATIONS_ENGINE === "claude")) {
    const model = p.model?.startsWith("claude-") ? p.model : process.env.ANTHROPIC_MODEL ?? "claude-opus-5-5";
    return anthropicProvider({ name: "Claude (environment key)", model });
  }
  return null;
}

export async function resolveAgent(key: AgentKey) {
  const profile = await loadProfile(key);
  const provider = profile.enabled ? await resolveProvider(key, profile) : null;
  return { profile, provider };
}
