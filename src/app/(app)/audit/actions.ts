"use server";

import { db } from "@/lib/db";
import { verifyAuditChainIntegrity } from "@/lib/audit";

export async function listAuditLogAction() {
  return db.auditLog.findMany({
    orderBy: { createdAt: "desc" },
    take: 200,
    include: {
      actor: { select: { name: true, email: true } },
      case: { select: { title: true, sourceType: true } },
    },
  });
}

export async function verifyAuditIntegrityAction() {
  return verifyAuditChainIntegrity();
}
