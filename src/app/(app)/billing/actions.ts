"use server";

import { revalidatePath } from "next/cache";

import { requireSession, requireOrgContext } from "@/lib/tenant";
import { db } from "@/lib/db";
import { listInvoices, requestBillingChange } from "@/lib/billing/service";

export async function getMyBillingAction() {
  const ctx = await requireSession();
  const organizationId = requireOrgContext(ctx);

  const [organization, rawSubscriptions, invoices] = await Promise.all([
    db.organization.findUniqueOrThrow({ where: { id: organizationId } }),
    db.subscription.findMany({
      where: { organizationId },
      include: { plan: true },
      orderBy: { startedAt: "desc" },
    }),
    listInvoices({ organizationId }),
  ]);

  // Plan.priceMonthly is a Prisma Decimal — not a plain object, so it
  // can't cross into a Client Component as-is (see billing/service.ts's
  // listPlans() for the same fix applied there).
  const subscriptions = rawSubscriptions.map((s) => ({
    ...s,
    plan: { ...s.plan, priceMonthly: Number(s.plan.priceMonthly) },
  }));

  return { organization, subscriptions, invoices };
}

export async function requestBillingChangeAction(message: string) {
  const ctx = await requireSession();
  const organizationId = requireOrgContext(ctx);
  await requestBillingChange(organizationId, message, ctx.userId);
  revalidatePath("/billing");
}
