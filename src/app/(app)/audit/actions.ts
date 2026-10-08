"use server";

import { db } from "@/lib/db";
import { verifyAuditChainIntegrity } from "@/lib/audit";
import { requireSession, tenantWhere } from "@/lib/tenant";

export async function listAuditLogAction() {
  const ctx = await requireSession();
  return db.auditLog.findMany({
    where: tenantWhere(ctx),
    orderBy: { createdAt: "desc" },
    take: 200,
    include: {
      actor: { select: { name: true, email: true } },
      case: { select: { title: true, sourceType: true } },
    },
  });
}

// Deliberately unscoped — the hash chain is one single global sequence
// (see src/lib/audit.ts), so "integrity" is a whole-chain property that
// can't be verified per-tenant. It returns only a boolean, no log
// contents, so there's nothing cross-tenant to leak.
export async function verifyAuditIntegrityAction() {
  await requireSession();
  return verifyAuditChainIntegrity();
}
