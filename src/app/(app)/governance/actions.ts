"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requireAdmin, requireUser } from "@/lib/session";
import { issueAgentIdentity } from "@/lib/governance/agents";
import { runScenario, globalPurge, getAllScenarios } from "@/lib/governance/simulator";
import {
  restoreAgent,
  confirmBreach,
  getAgentInvestigation,
} from "@/lib/governance/investigation";

export async function listAgentsAction() {
  await requireUser();
  return db.agent.findMany({ orderBy: { lastUpdateAt: "desc" } });
}

export async function listScenariosAction() {
  await requireUser();
  return getAllScenarios().map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    severity: s.severity,
  }));
}

export async function issueIdentityAction(name: string) {
  const { id: actorId } = await requireUser();
  const agent = await issueAgentIdentity(name, actorId);
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name };
}

export async function runScenarioAction(scenarioId: string) {
  const { id: actorId } = await requireUser();
  const result = await runScenario(scenarioId, actorId);
  revalidatePath("/governance");
  revalidatePath("/");
  return result;
}

export async function globalPurgeAction() {
  const { id: actorId } = await requireAdmin();
  const count = await globalPurge(actorId);
  revalidatePath("/governance");
  return count;
}

export async function investigateAgentAction(agentId: string) {
  await requireUser();
  return getAgentInvestigation(agentId);
}

export async function restoreAgentAction(agentId: string, justification: string) {
  const { id: actorId } = await requireUser();
  await restoreAgent(agentId, justification, actorId);
  revalidatePath("/governance");
}

export async function confirmBreachAction(agentId: string, notes: string) {
  const { id: actorId } = await requireUser();
  await confirmBreach(agentId, notes, actorId);
  revalidatePath("/governance");
}
