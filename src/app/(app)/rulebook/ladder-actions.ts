"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import type { PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { can } from "@/lib/rbac";
import { requireUser, type SessionUser } from "@/lib/session";
import { RULED_ACTIONS } from "@/lib/rulebook/schema";
import { MAX_LEVEL, PROMOTION, promotionCheck } from "@/lib/shadow/ladder";
import { decidePromotion, ladderStats, proposePromotion, setAutonomyLevel, startShadowMode } from "@/lib/shadow/service";
import { action } from "@/lib/action";
import { changeActorOf } from "@/lib/changes/rules";

// The autonomy ladder: staff who configure AI start shadow mode, lower a
// level at once, or propose a promotion. A promotion takes effect once the
// client (its admin, or staff on its recorded instruction) and HELIOS (an
// approver other than whoever proposed it) have both approved it.
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
const ruledAction = z.enum(RULED_ACTIONS);
const done = () => revalidatePath("/rulebook");

export const startShadowModeAction = action(async function startShadowModeAction(tenantId: string) {
  const user = await actor(tenantId, "manage");
  await startShadowMode(tenantId, who(user));
  done();
});

// Lowering is always allowed; raising goes through a promotion.
export const lowerLevelAction = action(async function lowerLevelAction(tenantId: string, actionType: string, level: number, reason: string) {
  const user = await actor(tenantId, "manage");
  const a = ruledAction.parse(actionType) as PlaybookActionType;
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType: a } } });
  if (!row) throw new Error("Start shadow mode for this client first");
  if (level >= row.level) throw new Error("Raise a level through a promotion the client approves");
  if (reason.trim().length < 3) throw new Error("Say why");
  await setAutonomyLevel(tenantId, a, z.number().int().min(0).max(MAX_LEVEL).parse(level), who(user), reason.trim());
  done();
});

// Staff propose a promotion when the shadow record supports it.
export const proposePromotionAction = action(async function proposePromotionAction(tenantId: string, actionType: string) {
  await actor(tenantId, "manage");
  const a = ruledAction.parse(actionType) as PlaybookActionType;
  const row = await db.autonomyLevel.findUnique({ where: { tenantId_actionType: { tenantId, actionType: a } } });
  if (!row) throw new Error("Start shadow mode for this client first");
  const stats = (await ladderStats(tenantId, new Date(Date.now() - PROMOTION.windowDays * 86_400_000))).byAction.get(a);
  const check = promotionCheck(row.level, stats ?? { decisions: 0, agreed: 0, falseContainments: 0, criticalFalseContainments: 0, misses: 0 });
  if (!check.eligible) throw new Error(`Not yet: ${check.reasons.join("; ")}`);
  if (row.proposedLevel != null) throw new Error("A promotion is already waiting for approval");
  await proposePromotion(tenantId, a, row.level, stats!, changeActorOf(await requireUser()));
  done();
  revalidatePath("/changes");
});

export const decidePromotionAction = action(async function decidePromotionAction(tenantId: string, actionType: string, approve: boolean, note: string, side?: "client" | "helios") {
  const user = await actor(tenantId, "approve");
  await decidePromotion(tenantId, ruledAction.parse(actionType) as PlaybookActionType, approve, changeActorOf(user), String(note ?? "").slice(0, 1000), user.isClient ? "client" : side === "client" ? "client" : "helios");
  done();
  revalidatePath("/changes");
});

// Lift the circuit breaker once the connector problem is understood.
export const resumeAutomationAction = action(async function resumeAutomationAction(tenantId: string) {
  const user = await actor(tenantId, "manage");
  const { resumeAutomation } = await import("@/lib/connectors/safety");
  await resumeAutomation(tenantId, who(user));
  done();
});
