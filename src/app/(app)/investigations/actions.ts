"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
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
  const caseId = await createInvestigation(title, details, linkedCaseId || undefined);
  revalidatePath("/investigations");
  revalidatePath("/");
  return caseId;
}

export async function listInvestigationsAction() {
  return listInvestigations();
}

export async function getInvestigationAction(caseId: string) {
  return getInvestigation(caseId);
}

export async function listLinkableCasesAction() {
  return db.case.findMany({
    where: { sourceType: "SIEM_ALERT" },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: { id: true, title: true, severity: true },
  });
}
