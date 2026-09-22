"use server";

import { revalidatePath } from "next/cache";

import { analyzeEmail, getEmailCase, listEmailCases } from "@/lib/forensics/service";
import { detonateUrl } from "@/lib/forensics/sandbox";
import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";

export async function analyzeEmailAction(formData: FormData) {
  const file = formData.get("file") as File | null;
  if (!file) throw new Error("No file provided");

  const buffer = Buffer.from(await file.arrayBuffer());
  const caseId = await analyzeEmail(buffer);
  revalidatePath("/forensics");
  revalidatePath("/");
  return caseId;
}

export async function listEmailCasesAction() {
  return listEmailCases();
}

export async function getEmailCaseAction(caseId: string) {
  return getEmailCase(caseId);
}

export async function detonateUrlAction(url: string, caseId: string) {
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
    action: "forensics.url_detonated",
    detail: { url, score: result.score, error: result.error },
  });

  revalidatePath("/forensics");
  return result;
}
