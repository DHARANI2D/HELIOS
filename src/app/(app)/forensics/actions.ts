"use server";

import { revalidatePath } from "next/cache";

import { analyzeEmail, getEmailCase, listEmailCases } from "@/lib/forensics/service";
import { detonateUrl } from "@/lib/forensics/sandbox";
import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { requireSession, tenantWhere } from "@/lib/tenant";

export async function analyzeEmailAction(formData: FormData) {
  const ctx = await requireSession();
  const file = formData.get("file") as File | null;
  if (!file) throw new Error("No file provided");

  const buffer = Buffer.from(await file.arrayBuffer());
  const caseId = await analyzeEmail(buffer, ctx.organizationId);
  revalidatePath("/forensics");
  revalidatePath("/");
  return caseId;
}

export async function listEmailCasesAction() {
  const ctx = await requireSession();
  return listEmailCases(tenantWhere(ctx));
}

export async function getEmailCaseAction(caseId: string) {
  const ctx = await requireSession();
  return getEmailCase(caseId, tenantWhere(ctx));
}

export async function detonateUrlAction(url: string, caseId: string) {
  const ctx = await requireSession();
  // Confirm the caller actually owns this case before attaching a
  // Detection to it — Detection rows have no organizationId of their own,
  // they inherit scope from their parent Case.
  const kase = await db.case.findFirst({ where: { id: caseId, ...tenantWhere(ctx) } });
  if (!kase) throw new Error("Case not found");

  const result = await detonateUrl(url);

  await db.detection.create({
    data: {
      caseId,
      source: "EMAIL_SANDBOX_DETONATION",
      ruleId: `sandbox@@${Date.now()}`,
      title: `Sandbox detonation: ${url}`,
      severity: result.score >= 40 ? "HIGH" : result.score > 0 ? "MEDIUM" : "INFO",
      evidence: result as never,
    },
  });

  await logAction({
    caseId,
    organizationId: kase.organizationId,
    action: "forensics.url_detonated",
    detail: { url, score: result.score, error: result.error },
  });

  revalidatePath("/forensics");
  return result;
}
