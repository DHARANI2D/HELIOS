"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { auth } from "@/lib/auth";
import { issueAgentIdentity } from "@/lib/governance/agents";
import { runScenario, globalPurge, getAllScenarios } from "@/lib/governance/simulator";
import {
  restoreAgent,
  confirmBreach,
  getAgentInvestigation,
} from "@/lib/governance/investigation";

export async function listAgentsAction() {
  return db.agent.findMany({ orderBy: { lastUpdateAt: "desc" } });
}

export async function listScenariosAction() {
  return getAllScenarios().map((s) => ({
    id: s.id,
    name: s.name,
    description: s.description,
    severity: s.severity,
  }));
}

async function requireUserId() {
  const session = await auth();
  return session?.user?.id;
}

export async function issueIdentityAction(name: string) {
  const actorId = await requireUserId();
  const agent = await issueAgentIdentity(name, actorId);
  revalidatePath("/governance");
  return { id: agent.id, name: agent.name };
}

export async function runScenarioAction(scenarioId: string) {
  const result = await runScenario(scenarioId);
  revalidatePath("/governance");
  revalidatePath("/");
  return result;
}

export async function globalPurgeAction() {
  const count = await globalPurge();
  revalidatePath("/governance");
  return count;
}

export async function investigateAgentAction(agentId: string) {
  return getAgentInvestigation(agentId);
}

export async function restoreAgentAction(agentId: string, justification: string) {
  const actorId = await requireUserId();
  await restoreAgent(agentId, justification, actorId);
  revalidatePath("/governance");
}

export async function confirmBreachAction(agentId: string, notes: string) {
  const actorId = await requireUserId();
  await confirmBreach(agentId, notes, actorId);
  revalidatePath("/governance");
}
