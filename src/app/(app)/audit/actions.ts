"use server";

import { verifyAuditChain } from "@/lib/audit";
import { requirePermission } from "@/lib/session";
import { action } from "@/lib/action";

export const verifyAuditChainAction = action(async function verifyAuditChainAction() {
  await requirePermission("audit.view");
  return verifyAuditChain();
});
