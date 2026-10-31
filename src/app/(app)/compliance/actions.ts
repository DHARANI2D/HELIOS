"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { db } from "@/lib/db";
import { assertCaseAccess } from "@/lib/access";
import { requirePermission, type SessionUser } from "@/lib/session";
import { can, type Permission } from "@/lib/rbac";
import { SUBMIT_CHANNELS, type SubmitChannel } from "@/lib/compliance/notices";
import { addUpdate, approveNotice, extendDeadline, markNotRequired, openCertIn, openDpdp, reopenNotice, requestApproval, saveNotice, setClockStart, submitNotice } from "@/lib/compliance/service";
import { action } from "@/lib/action";

// Regulatory notices from the case page. Every action re-checks that the
// user can see the case (clients only their own), then hands off to
// lib/compliance/service, which enforces the workflow.

async function forCase(caseId: string, permission: Permission): Promise<SessionUser> {
  const user = await requirePermission(permission);
  await assertCaseAccess(user, caseId);
  return user;
}

async function forNotice(id: string, permission: Permission | Permission[]) {
  const perms = Array.isArray(permission) ? permission : [permission];
  const user = await requirePermission("compliance.view");
  if (!perms.some((p) => can(user, p))) throw new Error("You don't have permission to do that");
  const n = await db.regulatoryNotice.findUnique({ where: { id }, select: { caseId: true } });
  if (!n) throw new Error("Not found");
  await assertCaseAccess(user, n.caseId);
  return { user, caseId: n.caseId };
}

function done(caseId: string) {
  revalidatePath(`/cases/${caseId}`);
  revalidatePath("/compliance");
}

const when = z.iso.datetime({ offset: true }).transform((s) => new Date(s));
const reason = z.string().trim().max(1000);

export const openCertInAction = action(async function openCertInAction(caseId: string, input: { categories: string[]; clockStartAt?: string | null; reason?: string }) {
  const user = await forCase(caseId, "compliance.prepare");
  const at = input.clockStartAt ? when.parse(input.clockStartAt) : undefined;
  if (at && !reason.min(1).safeParse(input.reason).success) throw new Error("Say why the incident was noticed at that time");
  await openCertIn(caseId, { actor: user, categories: z.array(z.string().max(8)).max(20).parse(input.categories), clockStartAt: at, reason: input.reason ? reason.parse(input.reason) : undefined });
  done(caseId);
});

export const openDpdpAction = action(async function openDpdpAction(caseId: string, input: { awareAt: string; principalsAffected: number | null; dataCategories: string[] }) {
  const user = await forCase(caseId, "compliance.prepare");
  await openDpdp(caseId, user, {
    awareAt: when.parse(input.awareAt),
    principalsAffected: z.number().int().min(0).nullable().parse(input.principalsAffected),
    dataCategories: z.array(z.string().trim().min(1).max(120)).max(40).parse(input.dataCategories),
  });
  done(caseId);
});

export const saveNoticeAction = action(async function saveNoticeAction(id: string, input: { content: unknown; categories?: string[] }) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  try {
    await saveNotice(id, user, { content: input.content, categories: input.categories ? z.array(z.string().max(8)).max(20).parse(input.categories) : undefined });
  } catch (err) {
    if (err instanceof z.ZodError) throw new Error(err.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
    throw err;
  }
  done(caseId);
});

export const setClockStartAction = action(async function setClockStartAction(id: string, at: string, why: string) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  await setClockStart(id, user, when.parse(at), reason.parse(why));
  done(caseId);
});

export const extendDeadlineAction = action(async function extendDeadlineAction(id: string, until: string, why: string) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  await extendDeadline(id, user, when.parse(until), reason.parse(why));
  done(caseId);
});

export const requestApprovalAction = action(async function requestApprovalAction(id: string) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  await requestApproval(id, user);
  done(caseId);
});

// Client admins approve their own; staff record the client's approval.
export const approveNoticeAction = action(async function approveNoticeAction(id: string, onBehalf?: { name: string; via: string }) {
  const { user, caseId } = await forNotice(id, ["compliance.approve", "compliance.prepare"]);
  if (user.isClient && !can(user, "compliance.approve")) throw new Error("You don't have permission to do that");
  await approveNotice(id, user, onBehalf ? { name: reason.parse(onBehalf.name), via: reason.parse(onBehalf.via) } : undefined);
  done(caseId);
});

export const submitNoticeAction = action(async function submitNoticeAction(id: string, input: { via: string; reference?: string; recipientsCount?: number | null; note?: string }) {
  const { user, caseId } = await forNotice(id, ["compliance.prepare", "compliance.approve"]);
  const via = z.enum(Object.keys(SUBMIT_CHANNELS) as [SubmitChannel, ...SubmitChannel[]]).parse(input.via);
  if (via === "email" && !can(user, "compliance.prepare")) throw new Error("Record your own filing instead");
  await submitNotice(id, user, {
    via,
    reference: input.reference ? z.string().trim().max(200).parse(input.reference) : undefined,
    recipientsCount: input.recipientsCount != null ? z.number().int().min(0).parse(input.recipientsCount) : undefined,
    note: input.note ? reason.parse(input.note) : undefined,
  });
  done(caseId);
});

export const notRequiredAction = action(async function notRequiredAction(id: string, why: string) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  await markNotRequired(id, user, reason.min(1, "Say why it isn't needed").parse(why));
  done(caseId);
});

export const reopenNoticeAction = action(async function reopenNoticeAction(id: string) {
  const { user, caseId } = await forNotice(id, "compliance.prepare");
  await reopenNotice(id, user);
  done(caseId);
});

export const addUpdateAction = action(async function addUpdateAction(caseId: string) {
  const user = await forCase(caseId, "compliance.prepare");
  await addUpdate(caseId, user);
  done(caseId);
});
