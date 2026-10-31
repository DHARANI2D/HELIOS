"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission } from "@/lib/session";
import { assertCaseAccess } from "@/lib/access";
import { db } from "@/lib/db";
import { attachRunbook, deleteRunbook, installTemplates, removeFromCase, saveRunbook, setRunbookEnabled, setStep } from "@/lib/runbooks/service";
import type { RunbookInput } from "@/lib/runbooks/match";
import { action } from "@/lib/action";

const nameOf = (u: { name?: string | null; email?: string | null }) => u.name || u.email || "Someone";

// Runbooks: authoring (SOC managers and incident responders), and working
// them on a case (anyone who triages it).

const id = z.string().min(1);

export const saveRunbookAction = action(async function saveRunbookAction(runbookId: string | null, input: RunbookInput & { tenantId: string | null }) {
  const user = await requirePermission("operations.manage");
  const saved = await saveRunbook(runbookId ? id.parse(runbookId) : null, { ...input, tenantId: input.tenantId || null }, user.id);
  revalidatePath("/runbooks");
  return saved.id;
});

export const setRunbookEnabledAction = action(async function setRunbookEnabledAction(runbookId: string, enabled: boolean) {
  const user = await requirePermission("operations.manage");
  await setRunbookEnabled(id.parse(runbookId), !!enabled, user.id);
  revalidatePath("/runbooks");
});

export const deleteRunbookAction = action(async function deleteRunbookAction(runbookId: string) {
  const user = await requirePermission("operations.manage");
  await deleteRunbook(id.parse(runbookId), user.id);
  revalidatePath("/runbooks");
});

export const installTemplatesAction = action(async function installTemplatesAction() {
  const user = await requirePermission("operations.manage");
  const n = await installTemplates(user.id);
  revalidatePath("/runbooks");
  return n;
});

async function onCase(caseId: string) {
  const user = await requirePermission("cases.triage");
  await assertCaseAccess(user, caseId);
  return { user, actor: { id: user.id, name: nameOf(user) } };
}

export const attachRunbookAction = action(async function attachRunbookAction(caseId: string, runbookId: string) {
  const { actor } = await onCase(id.parse(caseId));
  await attachRunbook(caseId, id.parse(runbookId), actor);
  revalidatePath(`/cases/${caseId}`);
});

export const setStepAction = action(async function setStepAction(caseRunbookId: string, stepId: string, change: { state: string; note?: string }) {
  const cr = await db.caseRunbook.findUniqueOrThrow({ where: { id: id.parse(caseRunbookId) }, select: { caseId: true } });
  const { actor } = await onCase(cr.caseId);
  await setStep(caseRunbookId, id.parse(stepId), { state: z.enum(["done", "skipped", "open"]).parse(change.state), note: z.string().max(1000).optional().parse(change.note) }, actor);
  revalidatePath(`/cases/${cr.caseId}`);
});

export const removeCaseRunbookAction = action(async function removeCaseRunbookAction(caseRunbookId: string) {
  const cr = await db.caseRunbook.findUniqueOrThrow({ where: { id: id.parse(caseRunbookId) }, select: { caseId: true } });
  const { actor } = await onCase(cr.caseId);
  await removeFromCase(caseRunbookId, actor);
  revalidatePath(`/cases/${cr.caseId}`);
});
