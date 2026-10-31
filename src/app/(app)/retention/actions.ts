"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";

import { requirePermission } from "@/lib/session";
import { placeHold, releaseHold, setRetention } from "@/lib/retention/service";
import { action } from "@/lib/action";

// Log retention and legal holds: admins and SOC managers.

const done = () => revalidatePath("/retention");

export const setRetentionAction = action(async function setRetentionAction(tenantId: string, input: { hotDays: number; retentionDays: number }) {
  const user = await requirePermission("settings.manage");
  await setRetention(z.string().min(1).parse(tenantId), { hotDays: z.number().parse(input.hotDays), retentionDays: z.number().parse(input.retentionDays) }, user.id);
  done();
});

export const placeHoldAction = action(async function placeHoldAction(input: { tenantId: string; caseId?: string; reason: string; from: string; to?: string }) {
  const user = await requirePermission("settings.manage");
  const date = z.iso.date();
  await placeHold(
    {
      tenantId: z.string().min(1).parse(input.tenantId),
      caseId: input.caseId?.trim() || null,
      reason: z.string().max(2000).parse(input.reason),
      fromAt: new Date(`${date.parse(input.from)}T00:00:00Z`),
      toAt: input.to ? new Date(`${date.parse(input.to)}T23:59:59Z`) : null,
    },
    user.id,
  );
  done();
});

export const releaseHoldAction = action(async function releaseHoldAction(id: string, reason: string) {
  const user = await requirePermission("settings.manage");
  await releaseHold(id, z.string().max(2000).parse(reason), user.id);
  done();
});
