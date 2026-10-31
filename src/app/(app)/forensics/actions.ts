"use server";

import { revalidatePath } from "next/cache";

import { requirePermission } from "@/lib/session";
import { resolveTenantInput } from "@/lib/tenants";
import { logAction } from "@/lib/audit";
import { analyzeSubmission } from "@/lib/forensics/service";
import { detonateUrl } from "@/lib/forensics/sandbox";
import { action } from "@/lib/action";

const MAX_BYTES = 20 * 1024 * 1024;

export const analyzeSubmissionAction = action(async function analyzeSubmissionAction(formData: FormData) {
  const user = await requirePermission("forensics.run");
  const detonate = formData.get("detonate") === "on";
  const file = formData.get("file");
  const raw = String(formData.get("raw") ?? "");
  const archivePassword = String(formData.get("archivePassword") ?? "").slice(0, 200);

  let filename: string;
  let bytes: Uint8Array;
  if (file instanceof File && file.size > 0) {
    if (file.size > MAX_BYTES) throw new Error("File is larger than 20 MB");
    filename = file.name;
    bytes = new Uint8Array(await file.arrayBuffer());
  } else if (raw.trim()) {
    filename = "pasted-message.eml";
    bytes = new Uint8Array(Buffer.from(raw));
  } else {
    throw new Error("Upload an .eml / file or paste raw message source");
  }

  const tenantId = await resolveTenantInput(user, formData.get("tenantId"));
  const result = await analyzeSubmission({ filename, bytes, detonate, actorId: user.id, tenantId, archivePasswords: archivePassword ? [archivePassword] : [] });
  revalidatePath("/forensics");
  revalidatePath("/");
  return result;
});

// Standalone toolkit check (desas's "URL sandbox" tool) — no case filed.
export const detonateUrlAction = action(async function detonateUrlAction(url: string) {
  const user = await requirePermission("forensics.run");
  const result = await detonateUrl(url.trim());
  await logAction({ actorId: user.id, action: "forensics.url_detonated", detail: { url: result.url, finalUrl: result.finalUrl, score: result.score, error: result.error } });
  return result;
});
