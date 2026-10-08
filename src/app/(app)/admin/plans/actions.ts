"use server";

import { revalidatePath } from "next/cache";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { listPlans, createPlan, togglePlanActive, type PlanInput } from "@/lib/billing/service";

export async function listPlansAction() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  return listPlans();
}

export async function createPlanAction(input: PlanInput) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  const plan = await createPlan(input);
  revalidatePath("/admin/plans");
  return plan.id;
}

export async function togglePlanActiveAction(id: string, active: boolean) {
  const ctx = await requireSession();
  requirePlatformRole(ctx);
  await togglePlanActive(id, active);
  revalidatePath("/admin/plans");
}
