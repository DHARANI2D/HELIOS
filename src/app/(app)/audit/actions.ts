"use server";

import { verifyAuditChain } from "@/lib/audit";
import { requirePermission } from "@/lib/session";

export async function verifyAuditChainAction() {
  await requirePermission("audit.view");
  return verifyAuditChain();
}
