"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requireAdmin, requirePermission } from "@/lib/session";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { issueAgentIdentity } from "@/lib/governance/agents";
import { runScenario, globalPurge, getAllScenarios } from "@/lib/governance/simulator";
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
  return db.agent.findMany({ where: await tenantScope(user), orderBy: { lastUpdateAt: "desc" } });
}

export async function listScenariosAction() {
  await requirePermission("governance.manage");
  return getAllScenarios().map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    severity: s.severity,
  }));
}

export async function issueIdentityAction(name: string) {
  const user = await requirePermission("governance.manage");
  const agent = await issueAgentIdentity(name, user.id, await selectedTenantId(user));
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name };
}

export async function runScenarioAction(scenarioId: string) {
  const user = await requirePermission("governance.manage");
  const result = await runScenario(scenarioId, user.id, await selectedTenantId(user));
  revalidatePath("/governance");
  revalidatePath("/");
  return result;
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
