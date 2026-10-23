"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requireAdmin } from "@/lib/session";
import { decideExecution, runRetroactive } from "@/lib/playbooks/engine";
import { hasAnyCondition, triggerConditionSchema } from "@/lib/playbooks/trigger";

function revalidate(caseId?: string) {
  revalidatePath("/playbooks");
  revalidatePath("/");
  revalidatePath("/cases");
  if (caseId) revalidatePath(`/cases/${caseId}`);
}

// Approving containment is an admin decision; analysts can see and request.
export async function decideExecutionAction(executionId: string, decision: "approved" | "rejected", notes?: string) {
  const user = await requireAdmin();
  const execution = await decideExecution(executionId, decision, user.id, notes?.trim() || undefined);
  revalidate(execution.caseId);
  return { status: execution.status };
}

export async function togglePlaybookAction(playbookId: string, enabled: boolean) {
  const user = await requireAdmin();
  await db.playbook.update({ where: { id: playbookId }, data: { enabled } });
  await logAction({ actorId: user.id, action: enabled ? "playbook.enabled" : "playbook.disabled", detail: { playbookId } });
  revalidate();
}

export async function runRetroactiveAction(playbookId: string) {
  const user = await requireAdmin();
  const result = await runRetroactive(playbookId, user.id);
  revalidate();
  return result;
}

const ACTION_TYPES = [
  "ISOLATE_HOST",
  "BLOCK_IP",
  "NOTIFY_SLACK",
  "CREATE_TICKET",
  "KILL_PROCESS",
  "COLLECT_LOGS",
  "REVOKE_AGENT",
  "RESTORE_AGENT",
] as const;

const playbookSchema = z.object({
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().max(1000).optional(),
  triggerCondition: triggerConditionSchema.refine(hasAnyCondition, "Add at least one trigger condition"),
  autoExecute: z.boolean(),
  requireApproval: z.boolean(),
  priority: z.number().int().min(0).max(1000),
  actions: z
    .array(
      z.object({
        name: z.string().trim().min(1).max(120),
        actionType: z.enum(ACTION_TYPES),
        parameters: z.record(z.string(), z.union([z.string(), z.number()])),
      }),
    )
    .min(1, "Add at least one action")
    .max(20),
});

export type PlaybookInput = z.input<typeof playbookSchema>;

export async function savePlaybookAction(input: PlaybookInput, playbookId?: string) {
  const user = await requireAdmin();
  const data = playbookSchema.parse(input);
  const actions = data.actions.map((a, i) => ({ ...a, order: i + 1 }));

  const saved = playbookId
    ? await db.$transaction(async (tx) => {
        await tx.playbookAction.deleteMany({ where: { playbookId } });
        return tx.playbook.update({
          where: { id: playbookId },
          data: {
            name: data.name,
            description: data.description,
            triggerCondition: data.triggerCondition,
            autoExecute: data.autoExecute,
            requireApproval: data.requireApproval,
            priority: data.priority,
            actions: { create: actions },
          },
        });
      })
    : await db.playbook.create({
        data: {
          name: data.name,
          description: data.description,
          triggerCondition: data.triggerCondition,
          autoExecute: data.autoExecute,
          requireApproval: data.requireApproval,
          priority: data.priority,
          actions: { create: actions },
        },
      });

  await logAction({
    actorId: user.id,
    action: playbookId ? "playbook.updated" : "playbook.created",
    detail: { playbookId: saved.id, name: saved.name },
  });
  revalidate();
  return { id: saved.id };
}

export async function deletePlaybookAction(playbookId: string) {
  const user = await requireAdmin();
  const runs = await db.playbookExecution.count({ where: { playbookId } });
  if (runs > 0) {
    // Executions reference the playbook for the audit record; keep it, disabled.
    await db.playbook.update({ where: { id: playbookId }, data: { enabled: false } });
    await logAction({ actorId: user.id, action: "playbook.disabled", detail: { playbookId, reason: "delete requested; has execution history" } });
    revalidate();
    return { deleted: false };
  }
  await db.playbook.delete({ where: { id: playbookId } });
  await logAction({ actorId: user.id, action: "playbook.deleted", detail: { playbookId } });
  revalidate();
  return { deleted: true };
}
