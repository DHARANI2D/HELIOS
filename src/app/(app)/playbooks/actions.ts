"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { decideApproval } from "@/lib/playbooks/engine";
import { logAction } from "@/lib/audit";
import { requireSession, tenantWhere } from "@/lib/tenant";
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
  const ctx = await requireSession();

  const playbook = await db.playbook.create({
    data: {
      organizationId: ctx.organizationId,
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
    actorId: ctx.userId,
    organizationId: ctx.organizationId,
    action: "playbook.created",
    detail: { playbookId: playbook.id, name: playbook.name },
  });

  revalidatePath("/playbooks");
  return playbook.id;
}

export async function togglePlaybookAction(id: string, enabled: boolean) {
  const ctx = await requireSession();
  const { count } = await db.playbook.updateMany({
    where: { id, ...tenantWhere(ctx) },
    data: { enabled },
  });
  if (count === 0) throw new Error("Playbook not found");
  revalidatePath("/playbooks");
}

export async function listPlaybooksAction() {
  const ctx = await requireSession();
  return db.playbook.findMany({
    where: tenantWhere(ctx),
    include: { actions: true, _count: { select: { executions: true } } },
    orderBy: { createdAt: "desc" },
  });
}

export async function listExecutionsAction() {
  const ctx = await requireSession();
  return db.playbookExecution.findMany({
    where: { case: tenantWhere(ctx) },
    include: { playbook: true, case: { select: { title: true } } },
    orderBy: { startedAt: "desc" },
    take: 100,
  });
}

export async function listPendingApprovalsAction() {
  const ctx = await requireSession();
  return db.playbookExecution.findMany({
    where: { status: "PENDING_APPROVAL", case: tenantWhere(ctx) },
    include: { playbook: true, case: { select: { title: true, severity: true } } },
    orderBy: { startedAt: "desc" },
  });
}

export async function decideApprovalAction(
  executionId: string,
  decision: "approved" | "rejected",
  notes?: string,
) {
  const ctx = await requireSession();
  await decideApproval(executionId, ctx.userId, decision, notes, tenantWhere(ctx));
  revalidatePath("/playbooks");
}
