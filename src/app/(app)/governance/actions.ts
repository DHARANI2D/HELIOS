"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requireAdmin, requirePermission } from "@/lib/session";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { globalPurge, issueAgentIdentity, rotateAgentToken } from "@/lib/governance/agents";
import {
  restoreAgent,
  confirmBreach,
  getAgentInvestigation,
} from "@/lib/governance/investigation";

// Governed AI agents belong to the client tenant the switcher is focused on.

async function assertAgentInScope(agentId: string, user: Awaited<ReturnType<typeof requirePermission>>) {
  const agent = await db.agent.findFirst({ where: { id: agentId, ...(await tenantScope(user)) }, select: { id: true } });
  if (!agent) throw new Error("Agent not found");
}

export async function listAgentsAction() {
  const user = await requirePermission("governance.manage");
  return db.agent.findMany({
    where: await tenantScope(user),
    orderBy: { lastUpdateAt: "desc" },
    select: { id: true, name: true, trust: true, level: true, status: true, mode: true, tokenPrefix: true, tenant: { select: { name: true } } },
  });
}

// The agent's API token is returned once, here; only its hash is kept.
export async function issueIdentityAction(name: string) {
  const user = await requirePermission("governance.manage");
  const clean = name.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(clean)) throw new Error("Name: 3–64 letters, digits, dots, dashes or underscores");
  const { agent, token } = await issueAgentIdentity(clean, user.id, await selectedTenantId(user));
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name, token };
}

export async function rotateAgentTokenAction(agentId: string) {
  const user = await requirePermission("governance.manage");
  await assertAgentInScope(agentId, user);
  const { agent, token } = await rotateAgentToken(agentId, user.id);
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name, token };
}

// Revokes every agent in the focused tenant (all tenants when unfocused).
export async function globalPurgeAction() {
  const user = await requireAdmin();
  const count = await globalPurge(user.id, await selectedTenantId(user));
  revalidatePath("/governance");
  return count;
}

export async function investigateAgentAction(agentId: string) {
  const user = await requirePermission("governance.manage");
  await assertAgentInScope(agentId, user);
  return getAgentInvestigation(agentId);
}

export async function restoreAgentAction(agentId: string, justification: string) {
  const user = await requirePermission("governance.manage");
  await assertAgentInScope(agentId, user);
  await restoreAgent(agentId, justification, user.id);
  revalidatePath("/governance");
}

export async function confirmBreachAction(agentId: string, notes: string) {
  const user = await requirePermission("governance.manage");
  await assertAgentInScope(agentId, user);
  await confirmBreach(agentId, notes, user.id);
  revalidatePath("/governance");
}
