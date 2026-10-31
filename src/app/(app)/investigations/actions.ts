"use server";

import { after } from "next/server";
import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { requirePermission } from "@/lib/session";
import { assertCaseAccess } from "@/lib/access";
import { resolveTenantInput } from "@/lib/tenants";
import { logAction } from "@/lib/audit";
import { resetPipeline, runInvestigationPipeline, startInvestigation } from "@/lib/investigations/service";
import { action } from "@/lib/action";

export const startInvestigationAction = action(async function startInvestigationAction(formData: FormData) {
  const user = await requirePermission("investigations.run");
  const title = String(formData.get("title") ?? "").trim();
  if (title.length < 3) throw new Error("Give the investigation a title (3+ characters)");

  const files = await Promise.all(
    formData
      .getAll("files")
      .filter((f): f is File => f instanceof File && f.size > 0)
      .map(async (f) => ({ name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) })),
  );

  const result = await startInvestigation({
    title,
    alertDetails: String(formData.get("alertDetails") ?? "").trim(),
    pastedLogs: String(formData.get("pastedLogs") ?? ""),
    files,
    archivePasswords: [String(formData.get("archivePassword") ?? "").slice(0, 200)].filter(Boolean),
    actorId: user.id,
    tenantId: await resolveTenantInput(user, formData.get("tenantId")),
  });

  // The swarm can take minutes with Claude; respond now and let the case page
  // poll metadata.pipeline for progress.
  after(() => runInvestigationPipeline(result.caseId));

  revalidatePath("/investigations");
  return result;
});

export const rerunInvestigationAction = action(async function rerunInvestigationAction(caseId: string) {
  const user = await requirePermission("investigations.run");
  await assertCaseAccess(user, caseId);
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { sourceType: true } });
  if (kase.sourceType !== "SOC_INVESTIGATION") throw new Error("Not an investigation case");
  await resetPipeline(caseId);
  await logAction({ actorId: user.id, caseId, action: "investigation.rerun_requested" });
  after(() => runInvestigationPipeline(caseId));
  revalidatePath(`/cases/${caseId}`);
});
