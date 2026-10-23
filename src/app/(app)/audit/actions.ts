"use server";

import { verifyAuditChain } from "@/lib/audit";
import { requireUser } from "@/lib/session";

export async function verifyAuditChainAction() {
  await requireUser();
  return verifyAuditChain();
}
