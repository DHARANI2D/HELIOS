"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission } from "@/lib/session";
import { assertCaseAccess } from "@/lib/access";
import { db } from "@/lib/db";
import { operationsSchema, setSetting } from "@/lib/settings";
import { logAction } from "@/lib/audit";
import { acknowledgePage, addOverride, deleteShift, generateShifts, pageOnCall } from "@/lib/operations/paging";
import { submitQaReview } from "@/lib/operations/qa";
import { action } from "@/lib/action";

const nameOf = (u: { name?: string | null; email?: string | null }) => u.name || u.email || "Someone";

// SOC operations: the on-call rota and pages, operations settings, QA reviews.

const done = (caseId?: string | null) => {
  revalidatePath("/operations");
  if (caseId) revalidatePath(`/cases/${caseId}`);
};
const when = z.iso.datetime({ offset: true }).transform((s) => new Date(s));

export const generateRotaAction = action(async function generateRotaAction(input: { userIds: string[]; from: string; shiftHours: number; shifts: number; withBackup: boolean }) {
  const user = await requirePermission("operations.manage");
  const n = await generateShifts({ userIds: z.array(z.string().min(1)).max(50).parse(input.userIds), from: when.parse(input.from), shiftHours: z.number().parse(input.shiftHours), shifts: z.number().int().parse(input.shifts), withBackup: !!input.withBackup }, user.id);
  done();
  return n;
});

export const addOverrideAction = action(async function addOverrideAction(input: { userId: string; role: string; startsAt: string; endsAt: string; note: string }) {
  const user = await requirePermission("operations.manage");
  await addOverride({ userId: z.string().min(1).parse(input.userId), role: z.enum(["primary", "backup"]).parse(input.role), startsAt: when.parse(input.startsAt), endsAt: when.parse(input.endsAt), note: z.string().max(300).parse(input.note ?? "") }, user.id);
  done();
});

export const deleteShiftAction = action(async function deleteShiftAction(id: string) {
  const user = await requirePermission("operations.manage");
  await deleteShift(z.string().min(1).parse(id), user.id);
  done();
});

export const acknowledgePageAction = action(async function acknowledgePageAction(id: string) {
  const user = await requirePermission("operations.view");
  const page = await acknowledgePage(z.string().min(1).parse(id), { id: user.id, name: nameOf(user) });
  done(page.caseId);
});

// A page raised by hand, about a case or not.
export const pageOnCallAction = action(async function pageOnCallAction(input: { caseId?: string | null; message: string }) {
  const user = await requirePermission("cases.escalate");
  const message = z.string().trim().min(3, "Say what it's about").max(500).parse(input.message);
  const kase = input.caseId ? (await assertCaseAccess(user, input.caseId), await db.case.findUniqueOrThrow({ where: { id: input.caseId }, select: { id: true, title: true, tenantId: true, severity: true } })) : null;
  const { page } = await pageOnCall({ key: `manual:${user.id}:${Date.now()}`, title: kase ? `${nameOf(user)} needs help: ${kase.title}` : `${nameOf(user)}: ${message.slice(0, 120)}`, body: message, caseId: kase?.id, tenantId: kase?.tenantId, severity: kase?.severity, createdById: user.id });
  done(kase?.id);
  return { level: page.level, paged: page.pagedIds.length };
});

export const saveOperationsSettingsAction = action(async function saveOperationsSettingsAction(input: unknown) {
  const user = await requirePermission("operations.manage");
  const value = operationsSchema.parse(input);
  await setSetting("operations", value, user.id);
  await logAction({ actorId: user.id, action: "settings.operations_changed", detail: value });
  done();
});

export const submitQaReviewAction = action(async function submitQaReviewAction(id: string, input: { actions: Record<string, string>; verdictRight: boolean | null; notes: string }) {
  const user = await requirePermission("qa.review");
  const review = await db.qaReview.findUniqueOrThrow({ where: { id: z.string().min(1).parse(id) }, select: { caseId: true } });
  await assertCaseAccess(user, review.caseId);
  const outcome = await submitQaReview(id, { actions: z.record(z.string(), z.enum(["right", "wrong"])).parse(input.actions ?? {}), verdictRight: input.verdictRight == null ? null : !!input.verdictRight, notes: z.string().max(4000).parse(input.notes ?? "") }, { id: user.id, name: nameOf(user) });
  done(review.caseId);
  return outcome;
});
