"use server";

import { revalidatePath } from "next/cache";
import { after } from "next/server";
import { z } from "zod";
import type { PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { seal } from "@/lib/secrets";
import { setSetting } from "@/lib/settings";
import { AGENT_KEYS, AGENT_TYPES, PROVIDER_PRESETS, type AgentKey } from "@/lib/ai/catalog";
import { providerFromRow } from "@/lib/ai/resolve";
import { anthropicProvider } from "@/lib/ai/anthropic";
import { PROPOSABLE_ACTIONS } from "@/lib/ai/triage";
import { startEvaluation } from "@/lib/ai/evals/service";

function revalidate() {
  revalidatePath("/ai");
  revalidatePath("/investigations");
}

const settingsSchema = z.object({
  killSwitch: z.boolean(),
  firstResponse: z.boolean(),
  minSeverity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  maxAutoActionsPerHour: z.number().int().min(0).max(100),
});

export async function saveAiSettingsAction(input: z.input<typeof settingsSchema>) {
  const user = await requirePermission("ai.configure");
  const s = settingsSchema.parse(input);
  await setSetting("ai.killSwitch", s.killSwitch, user.id);
  await setSetting("ai.firstResponse.enabled", s.firstResponse, user.id);
  await setSetting("ai.firstResponse.minSeverity", s.minSeverity, user.id);
  await setSetting("ai.maxAutoActionsPerHour", s.maxAutoActionsPerHour, user.id);
  await logAction({ actorId: user.id, action: "ai.settings_changed", detail: s });
  revalidate();
}

// The kill switch has its own action so it's one click from anywhere.
export async function setKillSwitchAction(on: boolean) {
  const user = await requirePermission("ai.configure");
  await setSetting("ai.killSwitch", on, user.id);
  await logAction({ actorId: user.id, action: on ? "ai.kill_switch_on" : "ai.kill_switch_off" });
  revalidate();
}

const providerSchema = z.object({
  id: z.string().optional(),
  name: z.string().trim().min(2).max(80),
  kind: z.enum(["anthropic", "openai_compatible"]),
  baseUrl: z.string().trim().url().max(300).optional().or(z.literal("")),
  model: z.string().trim().min(1).max(120),
  apiKey: z.string().trim().max(400).optional(),
  isLocal: z.boolean(),
  isDefault: z.boolean(),
});

export async function saveProviderAction(input: z.input<typeof providerSchema>) {
  const user = await requirePermission("ai.configure");
  const p = providerSchema.parse(input);
  if (p.kind === "openai_compatible" && !p.baseUrl) throw new Error("Local / OpenAI-compatible providers need a base URL");
  if (p.baseUrl && !/^https?:\/\//.test(p.baseUrl)) throw new Error("Base URL must be http(s)");
  const data = {
    name: p.name,
    kind: p.kind,
    baseUrl: p.kind === "anthropic" ? null : p.baseUrl || null,
    model: p.model,
    isLocal: p.kind === "openai_compatible" ? p.isLocal : false,
    // A blank key on edit keeps the stored one.
    ...(p.apiKey ? { apiKeyCipher: seal(p.apiKey) } : {}),
  };
  if (p.id && !(await db.aiProvider.count({ where: { id: p.id, tenantId: null } }))) throw new Error("Not found");
  const saved = p.id ? await db.aiProvider.update({ where: { id: p.id }, data }) : await db.aiProvider.create({ data });
  if (p.isDefault) {
    await db.aiProvider.updateMany({ where: { id: { not: saved.id }, tenantId: null }, data: { isDefault: false } });
    await db.aiProvider.update({ where: { id: saved.id }, data: { isDefault: true } });
  }
  await logAction({ actorId: user.id, action: p.id ? "ai.provider_updated" : "ai.provider_added", detail: { providerId: saved.id, name: saved.name, kind: saved.kind, model: saved.model, isLocal: saved.isLocal, keyChanged: !!p.apiKey } });
  revalidate();
  return { id: saved.id };
}

export async function setProviderEnabledAction(id: string, enabled: boolean) {
  const user = await requirePermission("ai.configure");
  await db.aiProvider.update({ where: { id }, data: { enabled, ...(enabled ? {} : { isDefault: false }) } });
  await logAction({ actorId: user.id, action: enabled ? "ai.provider_enabled" : "ai.provider_disabled", detail: { providerId: id } });
  revalidate();
}

export async function setDefaultProviderAction(id: string | null) {
  const user = await requirePermission("ai.configure");
  await db.aiProvider.updateMany({ where: { tenantId: null }, data: { isDefault: false } });
  // Only a platform provider can be the default for everyone.
  if (id) await db.aiProvider.update({ where: { id, tenantId: null }, data: { isDefault: true, enabled: true } });
  await logAction({ actorId: user.id, action: "ai.default_provider_set", detail: { providerId: id } });
  revalidate();
}

export async function deleteProviderAction(id: string) {
  const user = await requirePermission("ai.configure");
  await db.aiProvider.delete({ where: { id } });
  await logAction({ actorId: user.id, action: "ai.provider_deleted", detail: { providerId: id } });
  revalidate();
}

// "env" tests the ANTHROPIC_API_KEY from the environment.
export async function testProviderAction(id: string) {
  const user = await requirePermission("ai.configure");
  if (id === "env") {
    const result = await anthropicProvider({ name: "Claude (environment key)", model: process.env.ANTHROPIC_MODEL ?? PROVIDER_PRESETS[0].defaultModel }).check();
    await logAction({ actorId: user.id, action: "ai.provider_tested", detail: { providerId: "env", ok: result.ok } });
    return result;
  }
  const row = await db.aiProvider.findUniqueOrThrow({ where: { id } });
  const result = await providerFromRow(row).check();
  await db.aiProvider.update({ where: { id }, data: { lastCheckedAt: new Date(), lastCheckOk: result.ok, lastCheckMessage: result.message.slice(0, 300) } });
  await logAction({ actorId: user.id, action: "ai.provider_tested", detail: { providerId: id, ok: result.ok } });
  revalidate();
  return result;
}

const ACTIONS = [...PROPOSABLE_ACTIONS] as [PlaybookActionType, ...PlaybookActionType[]];

const profileSchema = z.object({
  key: z.enum(AGENT_KEYS as [AgentKey, ...AgentKey[]]),
  enabled: z.boolean(),
  providerId: z.string().nullable(),
  model: z.string().trim().max(120).nullable(),
  autonomy: z.enum(["OFF", "SUGGEST", "CONTAIN_WITH_APPROVAL", "AUTO_CONTAIN"]),
  effort: z.enum(["low", "medium", "high"]),
  minConfidence: z.number().min(0).max(1),
  allowedActions: z.array(z.enum(ACTIONS)),
  instructions: z.string().max(4000).nullable(),
});

export async function saveAgentProfileAction(input: z.input<typeof profileSchema>) {
  const user = await requirePermission("ai.configure");
  const p = profileSchema.parse(input);
  if (p.providerId) await db.aiProvider.findFirstOrThrow({ where: { id: p.providerId, tenantId: null } });
  const data = {
    name: AGENT_TYPES[p.key].name,
    description: AGENT_TYPES[p.key].description,
    enabled: p.enabled,
    providerId: p.providerId,
    model: p.model || null,
    autonomy: p.autonomy,
    effort: p.effort,
    minConfidence: p.minConfidence,
    allowedActions: p.allowedActions,
    instructions: p.instructions?.trim() || null,
  };
  await db.aiAgentProfile.upsert({ where: { key: p.key }, update: data, create: { key: p.key, ...data } });
  await logAction({ actorId: user.id, action: "ai.profile_updated", detail: { ...p, instructions: p.instructions ? `${p.instructions.length} chars` : null } });
  revalidate();
}

const evalSchema = z.object({
  target: z.union([z.object({ kind: z.literal("builtin") }), z.object({ kind: z.literal("env") }), z.object({ kind: z.literal("provider"), id: z.string().min(1) })]),
  agentKey: z.enum(["triage", "phishing", "threat_intel"]),
});

// Scores a model on the golden set. The built-in engine takes a moment and
// returns its scorecard; a model takes a call per case, so it finishes after
// the response and the page shows it running until then.
export async function runEvaluationAction(input: z.input<typeof evalSchema>) {
  const user = await requirePermission("ai.configure");
  const { target, agentKey } = evalSchema.parse(input);
  // Client providers too: staff who configure AI manage every client's.
  if (target.kind === "provider" && !(await db.aiProvider.count({ where: { id: target.id } }))) throw new Error("Not found");
  const { model, done } = await startEvaluation(target, agentKey, user.id);
  if (target.kind === "builtin") {
    const card = await done;
    revalidate();
    return { model, finished: true, passed: card.passed, score: card.score };
  }
  after(() => done.catch((err) => console.error("evaluation failed", model, err)));
  revalidate();
  return { model, finished: false, passed: null, score: null };
}
