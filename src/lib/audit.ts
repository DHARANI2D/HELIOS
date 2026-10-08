import { createHash } from "node:crypto";

import { db } from "@/lib/db";

// Deterministic JSON serialization (recursive key sort) — JSON.stringify's
// array-replacer form only filters/orders top-level keys, which would
// silently mangle nested `detail` objects that happen to share key names.
//
// Date needs its own case: a raw Date embedded in `detail` has no own
// enumerable properties, so walking it with Object.keys (the plain-object
// branch below) silently canonicalizes it to "{}" — but Postgres's Json
// column (via Prisma) serializes it through Date.prototype.toJSON() into
// an ISO string instead. Those two didn't match, so any logAction() call
// whose `detail` embedded a Date (e.g. a scheduledAt field) computed a
// currentHash at write time that could never be reproduced by
// verifyAuditChainIntegrity's read-time recomputation — a real bug this
// found once src/lib/pentest.ts started passing a Date through.
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
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
  organizationId?: string | null;
  action: string;
  detail?: Record<string, unknown>;
}

// Arbitrary fixed key for the chain's advisory lock — just needs to be
// consistent across every logAction call so they serialize against each
// other (and only each other).
const CHAIN_LOCK_KEY = 847_213_659;

export async function logAction({ actorId, caseId, organizationId, action, detail }: LogActionInput) {
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

    // organizationId is deliberately NOT part of the hashed entry — it's
    // a column added after this chain already had real entries, and
    // folding it into the hash would invalidate every pre-existing row's
    // currentHash. It's a plain filterable column only.
    //
    // Every optional field is coalesced to null up front, once, so the
    // exact same value feeds both the hash and the Prisma write (no risk
    // of the hash seeing `undefined ?? null` while the write sees the raw
    // `undefined`). This wasn't the cause of the caseId-corruption bug
    // documented on AuditLog.case in schema.prisma (that one was a
    // Case-deletion FK cascade, not this function) but is worth keeping
    // as the one place that invariant is enforced.
    const coalescedActorId = actorId ?? null;
    const coalescedCaseId = caseId ?? null;
    const coalescedDetail = detail ?? null;

    const entry = { actorId: coalescedActorId, caseId: coalescedCaseId, action, detail: coalescedDetail, prevHash };
    const currentHash = createHash("sha256").update(canonicalJson(entry)).digest("hex");

    return tx.auditLog.create({
      data: {
        actorId: coalescedActorId,
        caseId: coalescedCaseId,
        organizationId: organizationId ?? null,
        action,
        detail: coalescedDetail as never,
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
