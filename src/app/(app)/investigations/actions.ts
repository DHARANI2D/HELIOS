"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requireSession, tenantWhere } from "@/lib/tenant";
import {
  createInvestigation,
  getInvestigation,
  listInvestigations,
} from "@/lib/investigations/service";

export async function createInvestigationAction(
  title: string,
  details: string,
  linkedCaseId?: string,
) {
  const ctx = await requireSession();
  const caseId = await createInvestigation(title, details, ctx.organizationId, linkedCaseId || undefined);
  revalidatePath("/investigations");
  revalidatePath("/");
  return caseId;
}

export async function listInvestigationsAction() {
  const ctx = await requireSession();
  return listInvestigations(tenantWhere(ctx));
}

export async function getInvestigationAction(caseId: string) {
  const ctx = await requireSession();
  return getInvestigation(caseId, tenantWhere(ctx));
}

export async function listLinkableCasesAction() {
  const ctx = await requireSession();
  return db.case.findMany({
    where: { sourceType: "SIEM_ALERT", ...tenantWhere(ctx) },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: { id: true, title: true, severity: true },
  });
}
