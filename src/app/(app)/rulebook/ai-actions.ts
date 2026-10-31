"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { sealFor } from "@/lib/keys";
import { can } from "@/lib/rbac";
import { requirePermission, requireUser, type SessionUser } from "@/lib/session";
import { AGENT_KEYS, type AgentKey } from "@/lib/ai/catalog";
import { clientEndpointFetch, providerFromRow } from "@/lib/ai/resolve";
import { assertPublicUrl } from "@/lib/net/public-fetch";
import { CLIENT_AGENTS } from "@/lib/ai/gateway";
import { action } from "@/lib/action";
import { providerColumns, providerInputSchema, providerSecret, type ProviderInput } from "@/lib/ai/provider-input";

// A client's AI setup: its own providers (bring your own key), which
// provider each agent uses, and its monthly budget. Staff who configure AI
// can change any client's; a client admin can change their own.
async function aiActor(tenantId: string): Promise<SessionUser> {
  const user = await requireUser();
  const allowed = user.isClient ? user.tenantId === tenantId && can(user, "rulebook.edit") : can(user, "ai.configure");
  if (!allowed) throw new Error("Not allowed");
  if (!(await db.tenant.count({ where: { id: tenantId } }))) throw new Error("Not found");
  return user;
}

function done() {
  revalidatePath("/rulebook");
  revalidatePath("/ai");
}

export const saveClientProviderAction = action(async function saveClientProviderAction(tenantId: string, input: ProviderInput) {
  const user = await aiActor(tenantId);
  const p = providerInputSchema.parse(input);
  if (p.id && !(await db.aiProvider.count({ where: { id: p.id, tenantId } }))) throw new Error("Not found");
  const secret = providerSecret(p);
  // A client's provider runs on the client's own account: never on the
  // platform's (an absent Bedrock credential would mean the server's AWS
  // role). A local server may not need a key.
  if (!p.id && !secret && p.kind !== "openai_compatible") throw new Error(p.kind === "bedrock" ? "Add a Bedrock API key or an access key pair" : "Add the API key for this provider");
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { name: true } });
  const columns = providerColumns(p);
  // HELIOS reaches a client's own endpoint only at a public https address,
  // unless the operator allows private ones (lib/ai/resolve).
  if (columns.baseUrl && clientEndpointFetch()) {
    await assertPublicUrl(columns.baseUrl).catch((e: Error) => {
      throw new Error(`${e.message}: HELIOS reaches a client's own model at a public https address (an operator running HELIOS inside the client's network can allow private ones)`);
    });
  }
  const data = {
    ...columns,
    // Provider names are unique platform-wide; the client's name prefixes its own.
    name: p.name.startsWith(`${tenant.name} · `) ? p.name : `${tenant.name} · ${p.name}`,
    tenantId,
    isDefault: false,
    // Sealed with the client's own data key (lib/keys).
    ...(secret ? { apiKeyCipher: await sealFor(tenantId, secret) } : {}),
  };
  const saved = p.id ? await db.aiProvider.update({ where: { id: p.id }, data }) : await db.aiProvider.create({ data });
  await logAction({ actorId: user.id, action: p.id ? "ai.client_provider_updated" : "ai.client_provider_added", detail: { tenantId, providerId: saved.id, name: saved.name, kind: saved.kind, model: saved.model, region: saved.region, keyChanged: !!secret } });
  done();
  return { id: saved.id };
});

export const deleteClientProviderAction = action(async function deleteClientProviderAction(tenantId: string, id: string) {
  const user = await aiActor(tenantId);
  const row = await db.aiProvider.findFirst({ where: { id, tenantId } });
  if (!row) throw new Error("Not found");
  await db.aiProvider.delete({ where: { id } });
  await logAction({ actorId: user.id, action: "ai.client_provider_deleted", detail: { tenantId, providerId: id, name: row.name } });
  done();
});

export const testClientProviderAction = action(async function testClientProviderAction(tenantId: string, id: string) {
  const user = await aiActor(tenantId);
  const row = await db.aiProvider.findFirst({ where: { id, tenantId } });
  if (!row) throw new Error("Not found");
  const result = await (await providerFromRow(row)).check();
  await db.aiProvider.update({ where: { id }, data: { lastCheckedAt: new Date(), lastCheckOk: result.ok, lastCheckMessage: result.message.slice(0, 300) } });
  await logAction({ actorId: user.id, action: "ai.provider_tested", detail: { tenantId, providerId: id, ok: result.ok } });
  done();
  return result;
});

const policySchema = z.object({
  defaults: z.record(z.string(), z.string().nullable()),
  monthlyBudgetUsd: z.number().min(0).max(1_000_000).nullable(),
});

export const saveClientAiPolicyAction = action(async function saveClientAiPolicyAction(tenantId: string, input: z.input<typeof policySchema>) {
  const user = await aiActor(tenantId);
  const p = policySchema.parse(input);
  const defaults: Record<string, string> = {};
  for (const [key, providerId] of Object.entries(p.defaults)) {
    if (!providerId || !CLIENT_AGENTS.includes(key as AgentKey)) continue;
    if (!(await db.aiProvider.count({ where: { id: providerId, OR: [{ tenantId: null }, { tenantId }] } }))) throw new Error("Unknown provider");
    defaults[key] = providerId;
  }
  const budget = p.monthlyBudgetUsd && p.monthlyBudgetUsd > 0 ? p.monthlyBudgetUsd : null;
  await db.tenantAiPolicy.upsert({
    where: { tenantId },
    update: { defaults, monthlyBudgetUsd: budget, updatedById: user.id },
    create: { tenantId, defaults, monthlyBudgetUsd: budget, updatedById: user.id },
  });
  await logAction({ actorId: user.id, action: "ai.client_policy_saved", detail: { tenantId, defaults, monthlyBudgetUsd: budget } });
  done();
});

// A user's own model per agent, used wherever a client's rulebook lets
// users choose (and the model is allowed there).
export const saveMyModelPreferenceAction = action(async function saveMyModelPreferenceAction(key: string, providerId: string | null) {
  const user = await requirePermission("ai.dispatch");
  if (!(AGENT_KEYS as string[]).includes(key)) throw new Error("Unknown agent");
  if (providerId && !(await db.aiProvider.count({ where: { id: providerId, enabled: true } }))) throw new Error("Unknown provider");
  const row = await db.user.findUniqueOrThrow({ where: { id: user.id }, select: { preferences: true } });
  const prefs = (row.preferences && typeof row.preferences === "object" ? row.preferences : {}) as Record<string, unknown>;
  const models = { ...((prefs.aiModels as Record<string, string> | undefined) ?? {}) };
  if (providerId) models[key] = providerId;
  else delete models[key];
  await db.user.update({ where: { id: user.id }, data: { preferences: { ...prefs, aiModels: models } } });
  done();
});
