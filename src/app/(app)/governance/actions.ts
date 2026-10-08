"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requireSession, tenantWhere } from "@/lib/tenant";
import { issueAgentIdentity } from "@/lib/governance/agents";
import { runScenario, globalPurge, getAllScenarios } from "@/lib/governance/simulator";
import {
  restoreAgent,
  confirmBreach,
  getAgentInvestigation,
} from "@/lib/governance/investigation";

export async function listAgentsAction() {
  const ctx = await requireSession();
  return db.agent.findMany({ where: tenantWhere(ctx), orderBy: { lastUpdateAt: "desc" } });
}

export async function listScenariosAction() {
  return getAllScenarios().map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    severity: s.severity,
  }));
}

export async function issueIdentityAction(name: string) {
  const ctx = await requireSession();
  const agent = await issueAgentIdentity(name, ctx.organizationId, ctx.userId);
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name };
}

export async function runScenarioAction(scenarioId: string) {
  const ctx = await requireSession();
  const result = await runScenario(scenarioId, ctx.organizationId);
  revalidatePath("/governance");
  revalidatePath("/");
  return result;
}

export async function globalPurgeAction() {
  const ctx = await requireSession();
  const count = await globalPurge(tenantWhere(ctx));
  revalidatePath("/governance");
  return count;
}

export async function investigateAgentAction(agentId: string) {
  const ctx = await requireSession();
  return getAgentInvestigation(agentId, tenantWhere(ctx));
}

export async function restoreAgentAction(agentId: string, justification: string) {
  const ctx = await requireSession();
  await restoreAgent(agentId, justification, tenantWhere(ctx), ctx.userId);
  revalidatePath("/governance");
}

export async function confirmBreachAction(agentId: string, notes: string) {
  const ctx = await requireSession();
  await confirmBreach(agentId, notes, tenantWhere(ctx), ctx.userId);
  revalidatePath("/governance");
}
