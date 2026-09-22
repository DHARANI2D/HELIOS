import { createHash } from "node:crypto";

import { db } from "@/lib/db";

// Deterministic JSON serialization (recursive key sort) — JSON.stringify's
// array-replacer form only filters/orders top-level keys, which would
// silently mangle nested `detail` objects that happen to share key names.
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const body = keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`)
    .join(",");
  return `{${body}}`;
}

// Generalized from aegis's audit/ledger.py AuditLedger — one hash-chained
// trail for every write action app-wide (not just agent governance
// decisions), per the unified AuditLog model.

export interface LogActionInput {
  actorId?: string;
  caseId?: string;
  action: string;
  detail?: Record<string, unknown>;
}

// Arbitrary fixed key for the chain's advisory lock — just needs to be
// consistent across every logAction call so they serialize against each
// other (and only each other).
const CHAIN_LOCK_KEY = 847_213_659;

export async function logAction({ actorId, caseId, action, detail }: LogActionInput) {
  return db.$transaction(async (tx) => {
    // A read-then-write hash chain is a classic race: two concurrent
    // calls can both read the same "latest" row before either writes,
    // then both chain off the same prevHash, forking the chain. Holding
    // a Postgres advisory lock for the transaction's duration serializes
    // every logAction call against every other one, so the read and the
    // write are atomic together.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${CHAIN_LOCK_KEY})`;

    const prevLog = await tx.auditLog.findFirst({ orderBy: { seq: "desc" } });
    const prevHash = prevLog?.currentHash ?? "GENESIS";

    const entry = { actorId: actorId ?? null, caseId: caseId ?? null, action, detail: detail ?? null, prevHash };
    const currentHash = createHash("sha256").update(canonicalJson(entry)).digest("hex");

    return tx.auditLog.create({
      data: {
        actorId,
        caseId,
        action,
        detail: detail as never,
        prevHash,
        currentHash,
      },
    });
  });
}

export async function verifyAuditChainIntegrity(): Promise<boolean> {
  const logs = await db.auditLog.findMany({ orderBy: { seq: "asc" } });

  let prevHash = "GENESIS";
  for (const log of logs) {
    const entry = {
      actorId: log.actorId,
      caseId: log.caseId,
      action: log.action,
      detail: log.detail,
      prevHash,
    };
    const expectedHash = createHash("sha256").update(canonicalJson(entry)).digest("hex");

    if (log.currentHash !== expectedHash || log.prevHash !== prevHash) {
      return false;
    }
    prevHash = log.currentHash;
  }
  return true;
}
