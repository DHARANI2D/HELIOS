import type { AiProvider } from "@prisma/client";
import type { z } from "zod";

import { db } from "@/lib/db";
import { notify, staffFor } from "@/lib/notifications";
import { severityRank } from "@/lib/severity";
import type { AgentKey } from "@/lib/ai/catalog";
import type { LlmProvider, StructuredRequest, TextRequest } from "@/lib/ai/provider";
import { Redactor, type KnownEntities } from "@/lib/ai/redact";
import { envClaude, envClaudeAvailable, forcedBuiltin, providerFromRow, type AgentProfileView, type AgentScope } from "@/lib/ai/resolve";
import { activeRulebook } from "@/lib/rulebook/service";
import type { Rulebook } from "@/lib/rulebook/schema";

// The one way an agent working for a client gets a model. The client's
// signed rulebook says what may run on its evidence (residency, allowed
// providers, masking, whether users may choose); its AI policy says which
// provider it prefers per agent and its monthly budget. The resolution —
// which rule picked the model, and what was skipped and why — is stored on
// every AI run.

export type ModelSource = "user" | "client" | "profile" | "platform" | "environment";

export interface Candidate {
  source: ModelSource;
  id: string | null;
  name: string;
  model: string;
  isLocal: boolean;
  region: string | null;
  // Set when the client brought this provider (its own key).
  tenantId: string | null;
}

export type DataRules = Pick<Rulebook["dataHandling"], "residency" | "regions" | "allowedProviders">;

export interface Resolution {
  source: ModelSource | "builtin";
  providerId: string | null;
  provider: string | null;
  model: string | null;
  isLocal: boolean;
  clientKey: boolean;
  reason: string;
  skipped: Array<{ name: string; source: ModelSource; why: string }>;
  rulebookVersion: number | null;
  redacted: boolean;
  autonomyCap: "SUGGEST" | null;
  capReason?: string;
}

const SOURCE_LABEL: Record<ModelSource, string> = {
  user: "the user's own choice",
  client: "the client's choice for this agent",
  profile: "the agent profile",
  platform: "the platform default",
  environment: "the platform's environment key",
};

// Why a candidate may not run this client's evidence, or null. Pure.
export function whyNot(c: Candidate, tenantId: string, rules: DataRules | null): string | null {
  if (c.tenantId && c.tenantId !== tenantId) return "belongs to another client";
  if (!rules) return null;
  if (rules.residency === "onprem" && !c.isLocal) return "the client allows on-premises models only";
  if (rules.residency === "region") {
    if (c.isLocal) return null;
    if (!c.region || !rules.regions.map((r) => r.toLowerCase()).includes(c.region.toLowerCase())) {
      return `runs ${c.region ? `in ${c.region}` : "in an unstated region"}; the client requires ${rules.regions.join(" or ") || "a named region"}`;
    }
  }
  // A client's own provider is allowed by being theirs.
  if (rules.allowedProviders.length && !c.tenantId && !(c.id && rules.allowedProviders.includes(c.id))) return "not on the client's allowed list";
  return null;
}

export function pickCandidate(candidates: Candidate[], tenantId: string, rules: DataRules | null) {
  const skipped: Resolution["skipped"] = [];
  for (const c of candidates) {
    const why = whyNot(c, tenantId, rules);
    if (!why) return { chosen: c, skipped };
    skipped.push({ name: c.name, source: c.source, why });
  }
  return { chosen: null, skipped };
}

// ---------------------------------------------------------------- budget

export function monthKey(now: Date) {
  return now.toISOString().slice(0, 7);
}

// This month's model spend HELIOS pays for on the client's behalf (runs on
// the client's own key are billed to them directly and don't count).
export async function clientAiSpend(tenantId: string, now = new Date()) {
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const runs = await db.aiRun.findMany({ where: { tenantId, createdAt: { gte: start } }, select: { model: true, inputTokens: true, outputTokens: true, resolution: true } });
  const billable = runs.filter((r) => !(r.resolution && typeof r.resolution === "object" && (r.resolution as { clientKey?: boolean }).clientKey));
  const { aiCostOf } = await import("@/lib/pricing/service");
  return { spent: await aiCostOf(billable), runs: runs.length, clientKeyRuns: runs.length - billable.length };
}

export async function budgetState(tenantId: string, now = new Date()) {
  const policy = await db.tenantAiPolicy.findUnique({ where: { tenantId } });
  if (!policy?.monthlyBudgetUsd) return { budget: null, spent: 0, pct: 0, reached: false };
  const { spent } = await clientAiSpend(tenantId, now);
  const pct = spent / policy.monthlyBudgetUsd;
  const month = monthKey(now);
  // One alert at 80% and one when it's reached, each month.
  if (pct >= 0.8 && policy.budgetAlertMonth !== month) {
    await db.tenantAiPolicy.update({ where: { tenantId }, data: { budgetAlertMonth: month } });
    const tenant = await db.tenant.findUnique({ where: { id: tenantId }, select: { name: true } });
    await notify(await staffFor(["SOC_MANAGER"], null), { kind: "ai", title: `${tenant?.name ?? "A client"} has used ${Math.round(pct * 100)}% of its AI budget`, body: `$${spent.toFixed(2)} of $${policy.monthlyBudgetUsd.toFixed(2)} this month. At 100%, low-severity cases fall back to the built-in engine.`, href: `/ai?tenant=${tenantId}` });
  }
  if (pct >= 1 && policy.budgetReachedMonth !== month) {
    await db.tenantAiPolicy.update({ where: { tenantId }, data: { budgetReachedMonth: month } });
  }
  return { budget: policy.monthlyBudgetUsd, spent, pct, reached: pct >= 1 };
}

// ---------------------------------------------------------------- resolution

function candidateOf(row: AiProvider, source: ModelSource, model?: string | null): Candidate {
  return { source, id: row.id, name: row.name, model: model || row.model, isLocal: row.isLocal, region: row.region, tenantId: row.tenantId };
}

function preferenceFor(preferences: unknown, key: AgentKey): string | null {
  const models = preferences && typeof preferences === "object" ? (preferences as { aiModels?: Record<string, string> }).aiModels : undefined;
  return typeof models?.[key] === "string" ? models[key] : null;
}

const builtin = (reason: string, skipped: Resolution["skipped"], rulebookVersion: number | null): Resolution => ({
  source: "builtin",
  providerId: null,
  provider: null,
  model: null,
  isLocal: true,
  clientKey: false,
  reason,
  skipped,
  rulebookVersion,
  redacted: false,
  autonomyCap: null,
});

export async function resolveForClient(key: AgentKey, profile: AgentProfileView, scope: AgentScope & { tenantId: string }) {
  const rb = await activeRulebook(scope.tenantId);
  const version = rb?.version ?? null;
  if (forcedBuiltin(key)) return { provider: null, redact: false, autonomyCap: null, resolution: builtin("HELIOS is set to the built-in engine", [], version) };

  const rules = rb?.body.dataHandling ?? null;
  const [policy, user, rows] = await Promise.all([
    db.tenantAiPolicy.findUnique({ where: { tenantId: scope.tenantId } }),
    scope.userId && rules?.allowUserChoice ? db.user.findUnique({ where: { id: scope.userId }, select: { preferences: true } }) : null,
    db.aiProvider.findMany({ where: { enabled: true, OR: [{ tenantId: null }, { tenantId: scope.tenantId }] } }),
  ]);
  const byId = new Map(rows.map((r) => [r.id, r]));
  const candidates: Candidate[] = [];
  const add = (row: AiProvider | undefined, source: ModelSource, model?: string | null) => row && candidates.push(candidateOf(row, source, model));

  const preferred = preferenceFor(user?.preferences, key);
  if (preferred) add(byId.get(preferred), "user");
  const clientDefault = policy?.defaults && typeof policy.defaults === "object" ? (policy.defaults as Record<string, string>)[key] : undefined;
  if (clientDefault) add(byId.get(clientDefault), "client");
  const platform = rows.filter((r) => !r.tenantId);
  if (profile.providerId) add(platform.find((r) => r.id === profile.providerId), "profile", profile.model);
  add(platform.find((r) => r.isDefault), "platform", profile.model);
  if (envClaudeAvailable()) {
    const env = envClaude(profile);
    candidates.push({ source: "environment", id: null, name: env.name, model: env.model, isLocal: false, region: null, tenantId: null });
  }

  const { chosen, skipped } = pickCandidate(candidates, scope.tenantId, rules);
  if (!chosen) {
    const why = skipped.length ? "no allowed model is configured for this client" : "no model is configured";
    return { provider: null, redact: false, autonomyCap: null, resolution: builtin(`Built-in engine: ${why}`, skipped, version) };
  }

  // Over budget: low-severity work moves to the built-in engine; high and
  // critical cases still get the model. The client's own key isn't metered.
  if (!chosen.tenantId && scope.severity && severityRank(scope.severity) < severityRank("HIGH")) {
    const budget = await budgetState(scope.tenantId);
    if (budget.reached) {
      return { provider: null, redact: false, autonomyCap: null, resolution: builtin(`Built-in engine: the client's monthly AI budget ($${budget.budget?.toFixed(2)}) is used up; only high and critical cases use a model`, skipped, version) };
    }
  }

  const row = chosen.id ? byId.get(chosen.id)! : null;
  const provider = row ? await providerFromRow(row, chosen.source === "profile" || chosen.source === "platform" ? profile.model : null) : envClaude(profile);
  const redact = !!rules?.redactPii && !provider.isLocal;

  // A model the client picked (rather than the SOC) acts on its own only
  // once it has passed the evaluation for this agent.
  let autonomyCap: "SUGGEST" | null = null;
  let capReason: string | undefined;
  if (chosen.source === "user" || chosen.source === "client") {
    const cap = await db.modelCapability.findUnique({ where: { model_agentKey: { model: provider.model, agentKey: key } } });
    if (!cap?.passed) {
      autonomyCap = "SUGGEST";
      capReason = cap ? `${provider.model} scored ${Math.round(cap.score * 100)}% on the ${key} evaluation, below the bar: suggestions only` : `${provider.model} hasn't been evaluated for ${key}: suggestions only until it passes`;
    }
  }

  const resolution: Resolution = {
    source: chosen.source,
    providerId: chosen.id,
    provider: provider.name,
    model: provider.model,
    isLocal: provider.isLocal,
    clientKey: !!chosen.tenantId,
    reason: `${provider.name} (${provider.model}) from ${SOURCE_LABEL[chosen.source]}${skipped.length ? `; skipped ${skipped.map((s) => `${s.name} (${s.why})`).join(", ")}` : ""}`,
    skipped,
    rulebookVersion: version,
    redacted: redact,
    autonomyCap,
    capReason,
  };
  return { provider, redact, autonomyCap, resolution };
}

// ---------------------------------------------------------------- masking

// The provider as the client's rules require: evidence masked on the way
// out, answers restored on the way back.
export function withRedaction(provider: LlmProvider, known: KnownEntities): { provider: LlmProvider; redactor: Redactor } {
  const redactor = new Redactor(known);
  const masked: LlmProvider = {
    ...provider,
    async structured<S extends z.ZodType>(request: StructuredRequest<S>) {
      const res = await provider.structured({ ...request, system: redactor.redact(request.system), user: redactor.redact(request.user) });
      return { ...res, data: redactor.restore(res.data) };
    },
    async text(request: TextRequest) {
      const res = await provider.text({ ...request, system: redactor.redact(request.system), user: redactor.redact(request.user) });
      return { ...res, data: redactor.restoreText(res.data) };
    },
  };
  return { provider: masked, redactor };
}

// ---------------------------------------------------------------- preview

// The agents that work on a client's cases, and which model each would get
// right now (without a case, so the budget fallback isn't applied).
export const CLIENT_AGENTS: AgentKey[] = ["triage", "phishing", "threat_intel", "report", "investigation"];

export async function previewClientModels(tenantId: string, userId?: string | null) {
  const { loadProfile } = await import("@/lib/ai/resolve");
  return Promise.all(
    CLIENT_AGENTS.map(async (key) => {
      const profile = await loadProfile(key);
      if (!profile.enabled) return { key, resolution: builtin(`${profile.name} is turned off`, [], null) };
      const r = await resolveForClient(key, profile, { tenantId, userId });
      return { key, resolution: r.resolution };
    }),
  );
}
