import { createHash } from "node:crypto";

import { db } from "@/lib/db";

// Deterministic JSON serialization (recursive key sort) — JSON.stringify's
// array-replacer form only filters/orders top-level keys, which would
// silently mangle nested `detail` objects that happen to share key names.
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const body = keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`)
    .join(",");
  return `{${body}}`;
}

// The hash must be computed over exactly what Postgres will hand back on
// verification. Round-tripping through JSON turns Dates into ISO strings and
// drops `undefined` keys the same way the jsonb column does — hashing the raw
// object instead would make any entry with a Date or optional field look
// tampered with.
function toStoredJson(detail: Record<string, unknown> | undefined) {
  if (detail === undefined) return null;
  return JSON.parse(JSON.stringify(detail)) as Record<string, unknown>;
}

export function computeEntryHash(entry: {
  actorId: string | null;
  caseId: string | null;
  action: string;
  detail: unknown;
  prevHash: string;
}) {
  return createHash("sha256").update(canonicalJson(entry)).digest("hex");
}

// Arbitrary constant key for pg_advisory_xact_lock — serializes appends so two
// concurrent writers can't both read the same tail and fork the chain.
const AUDIT_CHAIN_LOCK = 4_242_001;

// Generalized from aegis's audit/ledger.py AuditLedger — one hash-chained
// trail for every write action app-wide (not just agent governance
// decisions), per the unified AuditLog model.

export interface LogActionInput {
  actorId?: string;
  caseId?: string;
  action: string;
  detail?: Record<string, unknown>;
}

export async function logAction({ actorId, caseId, action, detail }: LogActionInput) {
  const storedDetail = toStoredJson(detail);

  return db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_CHAIN_LOCK})`;

    const prevLog = await tx.auditLog.findFirst({ orderBy: { seq: "desc" } });
    const prevHash = prevLog?.currentHash ?? "GENESIS";

    const currentHash = computeEntryHash({
      actorId: actorId ?? null,
      caseId: caseId ?? null,
      action,
      detail: storedDetail,
      prevHash,
    });

    return tx.auditLog.create({
      data: {
        actorId,
        caseId,
        action,
        detail: (storedDetail ?? undefined) as never,
        prevHash,
        currentHash,
      },
    });
  });
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  brokenAt?: { id: string; seq: number; reason: "hash_mismatch" | "link_mismatch" };
}

export async function verifyAuditChain(): Promise<ChainVerification> {
  const logs = await db.auditLog.findMany({ orderBy: { seq: "asc" } });

  let prevHash = "GENESIS";
  for (const log of logs) {
    if (log.prevHash !== prevHash) {
      return { valid: false, checked: logs.length, brokenAt: { id: log.id, seq: log.seq, reason: "link_mismatch" } };
    }
    const expectedHash = computeEntryHash({
      actorId: log.actorId,
      caseId: log.caseId,
      action: log.action,
      detail: log.detail,
      prevHash,
    });
    if (log.currentHash !== expectedHash) {
      return { valid: false, checked: logs.length, brokenAt: { id: log.id, seq: log.seq, reason: "hash_mismatch" } };
    }
    prevHash = log.currentHash;
  }
  return { valid: true, checked: logs.length };
}
