"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { auth } from "@/lib/auth";
import { decideApproval } from "@/lib/playbooks/engine";
import { logAction } from "@/lib/audit";
import type { CaseSeverity, CaseSource, PlaybookActionType } from "@prisma/client";

export interface CreatePlaybookInput {
  name: string;
  description: string;
  severity?: CaseSeverity;
  sourceType?: CaseSource;
  minRiskScore?: number;
  autoExecute: boolean;
  requireApproval: boolean;
  actions: { name: string; actionType: PlaybookActionType; parameters: Record<string, unknown> }[];
}

export async function createPlaybookAction(input: CreatePlaybookInput) {
  const session = await auth();

  const playbook = await db.playbook.create({
    data: {
      name: input.name,
      description: input.description,
      triggerCondition: {
        severity: input.severity,
        sourceType: input.sourceType,
        minRiskScore: input.minRiskScore,
      } as never,
      autoExecute: input.autoExecute,
      requireApproval: input.requireApproval,
      actions: {
        create: input.actions.map((a, i) => ({
          name: a.name,
          actionType: a.actionType,
          parameters: a.parameters as never,
          order: i,
        })),
      },
    },
  });

  await logAction({
    actorId: session?.user?.id,
    action: "playbook.created",
    detail: { playbookId: playbook.id, name: playbook.name },
  });

  revalidatePath("/playbooks");
  return playbook.id;
}

export async function togglePlaybookAction(id: string, enabled: boolean) {
  await db.playbook.update({ where: { id }, data: { enabled } });
  revalidatePath("/playbooks");
}

export async function listPlaybooksAction() {
  return db.playbook.findMany({
    include: { actions: true, _count: { select: { executions: true } } },
    orderBy: { createdAt: "desc" },
  });
}

export async function listExecutionsAction() {
  return db.playbookExecution.findMany({
    include: { playbook: true, case: { select: { title: true } } },
    orderBy: { startedAt: "desc" },
    take: 100,
  });
}

export async function listPendingApprovalsAction() {
  return db.playbookExecution.findMany({
    where: { status: "PENDING_APPROVAL" },
    include: { playbook: true, case: { select: { title: true, severity: true } } },
    orderBy: { startedAt: "desc" },
  });
}

export async function decideApprovalAction(
  executionId: string,
  decision: "approved" | "rejected",
  notes?: string,
) {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Not authenticated");

  await decideApproval(executionId, session.user.id, decision, notes);
  revalidatePath("/playbooks");
}
