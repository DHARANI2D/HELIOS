import type { AiAgentProfile, AiProvider, CaseSeverity } from "@prisma/client";

import { db } from "@/lib/db";
import { openSealed } from "@/lib/keys";
import { AGENT_TYPES, type AgentKey } from "@/lib/ai/catalog";
import type { Effort, LlmProvider } from "@/lib/ai/provider";
import { anthropicProvider, bedrockProvider, parseBedrockAuth } from "@/lib/ai/anthropic";
import { openAiCompatibleProvider } from "@/lib/ai/openai-compatible";
import { publicFetch } from "@/lib/net/public-fetch";

// Which model runs which agent. Order of precedence:
//   HELIOS_AI_ENGINE=builtin (or INVESTIGATIONS_ENGINE=heuristic for the
//   investigation swarm)  → deterministic engine everywhere
//   for a client: the user's choice (if the client allows it) → the
//   client's default for the agent → then as below, each only if the
//   client's rulebook allows that provider (lib/ai/gateway)
//   the agent profile's provider → the platform default provider →
//   an ANTHROPIC_API_KEY in the environment → deterministic engine.
// Client-owned providers are never used for anyone else.

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

// A client admin types their own provider's address; from a hosted HELIOS
// it may only reach public https hosts (not the cloud metadata endpoint or
// the platform's own network). An operator running HELIOS inside a client's
// network, where the client's model is on a private address, turns that off
// with HELIOS_ALLOW_PRIVATE_CLIENT_AI=1.
export function clientEndpointFetch(): typeof fetch | undefined {
  if (process.env.HELIOS_ALLOW_PRIVATE_CLIENT_AI === "1") return undefined;
  return ((url: string | URL | Request, init?: RequestInit) => publicFetch(String(url instanceof Request ? url.url : url), init)) as typeof fetch;
}

export async function providerFromRow(row: AiProvider, modelOverride?: string | null): Promise<LlmProvider> {
  const model = modelOverride || row.model;
  // A client's own key is sealed with that client's data key (lib/keys).
  const secret = row.apiKeyCipher ? await openSealed(row.apiKeyCipher) : undefined;
  if (row.kind === "anthropic") return anthropicProvider({ name: row.name, model, apiKey: secret });
  if (row.kind === "bedrock") {
    if (!row.region) throw new Error(`Provider ${row.name} has no AWS region`);
    const auth = parseBedrockAuth(secret);
    // Without credentials the server's own AWS identity answers, which a
    // client's provider must never borrow.
    if (!auth && row.tenantId) throw new Error(`Provider ${row.name} has no AWS credentials`);
    return bedrockProvider({ name: row.name, model, region: row.region, auth });
  }
  if (!row.baseUrl) throw new Error(`Provider ${row.name} has no base URL`);
  const guarded = row.tenantId ? clientEndpointFetch() : undefined;
  return openAiCompatibleProvider({ name: row.name, baseUrl: row.baseUrl, model, apiKey: secret, isLocal: row.isLocal, azure: row.kind === "azure_openai", fetch: guarded });
}

export async function resolveProvider(key: AgentKey, profile?: AgentProfileView): Promise<LlmProvider | null> {
  if (forcedBuiltin(key)) return null;
  const p = profile ?? (await loadProfile(key));

  const row = p.providerId
    ? await db.aiProvider.findFirst({ where: { id: p.providerId, enabled: true, tenantId: null } })
    : await db.aiProvider.findFirst({ where: { isDefault: true, enabled: true, tenantId: null } });
  if (row) return providerFromRow(row, p.model);

  if (envClaudeAvailable() || (key === "investigation" && process.env.INVESTIGATIONS_ENGINE === "claude")) {
    return envClaude(p);
  }
  return null;
}

function envClaude(p: AgentProfileView) {
  const model = p.model?.startsWith("claude-") ? p.model : process.env.ANTHROPIC_MODEL ?? "claude-opus-5-5";
  return anthropicProvider({ name: "Claude (environment key)", model });
}

// ---------------------------------------------------------------- per client

// Who an agent runs for. With a client, its rulebook and AI policy decide
// which model may run (lib/ai/gateway); without one, the platform settings.
export interface AgentScope {
  tenantId?: string | null;
  userId?: string | null;
  severity?: CaseSeverity | null;
}

export async function resolveAgent(key: AgentKey, scope: AgentScope = {}) {
  const profile = await loadProfile(key);
  if (!profile.enabled) return { profile, provider: null, resolution: null, redact: false, autonomyCap: null };
  if (!scope.tenantId) {
    const provider = await resolveProvider(key, profile);
    return { profile, provider, resolution: null, redact: false, autonomyCap: null };
  }
  const { resolveForClient } = await import("@/lib/ai/gateway");
  const r = await resolveForClient(key, profile, { ...scope, tenantId: scope.tenantId });
  return { profile, provider: r.provider, resolution: r.resolution, redact: r.redact, autonomyCap: r.autonomyCap };
}

export { envClaude, forcedBuiltin };
