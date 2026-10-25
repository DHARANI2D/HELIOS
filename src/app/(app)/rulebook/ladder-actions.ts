"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import type { PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { can } from "@/lib/rbac";
import { requireUser, type SessionUser } from "@/lib/session";
import { RULED_ACTIONS } from "@/lib/rulebook/schema";
import { MAX_LEVEL, PROMOTION, promotionCheck } from "@/lib/shadow/ladder";
import { decidePromotion, ladderStats, setAutonomyLevel, startShadowMode } from "@/lib/shadow/service";

// The autonomy ladder: staff who configure AI start shadow mode, lower a
// level, or propose a promotion; the client admin approves promotions (staff
// only on the client's recorded instruction).
async function actor(tenantId: string, need: "manage" | "approve"): Promise<SessionUser> {
  const user = await requireUser();
  const ok = user.isClient
    ? user.tenantId === tenantId && (need === "approve" ? can(user, "rulebook.sign") : false)
    : need === "approve" ? can(user, "rulebook.sign") : can(user, "ai.configure");
  if (!ok) throw new Error("Not allowed");
  if (!(await db.tenant.count({ where: { id: tenantId } }))) throw new Error("Not found");
  return user;
}

const who = (u: SessionUser) => ({ id: u.id, name: u.name ?? u.email ?? "user" });
const action = z.enum(RULED_ACTIONS);
const done = () => revalidatePath("/rulebook");

export async function startShadowModeAction(tenantId: string) {
  const user = await actor(tenantId, "manage");
  await startShadowMode(tenantId, who(user));
  done();
}

// Lowering is always allowed; raising goes through a promotion.
export async function lowerLevelAction(tenantId: string, actionType: string, level: number, reason: string) {
  const user = await actor(tenantId, "manage");
  const a = action.parse(actionType) as PlaybookActionType;
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType: a } } });
  if (!row) throw new Error("Start shadow mode for this client first");
  if (level >= row.level) throw new Error("Raise a level through a promotion the client approves");
  if (reason.trim().length < 3) throw new Error("Say why");
  await setAutonomyLevel(tenantId, a, z.number().int().min(0).max(MAX_LEVEL).parse(level), who(user), reason.trim());
  done();
}

// Staff propose a promotion when the shadow record supports it.
export async function proposePromotionAction(tenantId: string, actionType: string) {
  await actor(tenantId, "manage");
  const a = action.parse(actionType) as PlaybookActionType;
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType: a } } });
  if (!row) throw new Error("Start shadow mode for this client first");
  const stats = (await ladderStats(tenantId, new Date(Date.now() - PROMOTION.windowDays * 86_400_000))).byAction.get(a);
  const check = promotionCheck(row.level, stats ?? { decisions: 0, agreed: 0, falseContainments: 0, criticalFalseContainments: 0, misses: 0 });
  if (!check.eligible) throw new Error(`Not yet: ${check.reasons.join("; ")}`);
  await db.autonomyLevel.update({ where: { tenantId_actionType: { tenantId, actionType: a } }, data: { proposedLevel: row.level + 1, proposedAt: new Date(), proposalStats: JSON.parse(JSON.stringify(stats)) } });
  const admins = await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  const { notify } = await import("@/lib/notifications");
  await notify(admins.map((x) => x.id), { kind: "ai", title: "A promotion of AI autonomy is waiting for you", body: "Review the shadow-mode record and approve or decline it on your rulebook page.", href: "/rulebook" });
  done();
}

export async function decidePromotionAction(tenantId: string, actionType: string, approve: boolean, note: string) {
  const user = await actor(tenantId, "approve");
  await decidePromotion(tenantId, action.parse(actionType) as PlaybookActionType, approve, { ...who(user), isClient: user.isClient }, String(note ?? "").slice(0, 1000));
  done();
}
