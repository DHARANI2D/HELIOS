import { describe, it, expect } from "vitest";

import { logAction, verifyAuditChainIntegrity } from "./audit";
import { db } from "./db";

// Integration test against the real Postgres instance (Prisma-backed code
// isn't meaningfully unit-testable in isolation) — this is the module
// where two real bugs were found during the initial port (chain ordering
// under millisecond timestamp collisions, and a read-then-write race
// between concurrent writers), so it's worth verifying against the real
// database rather than mocking Prisma away.

describe("audit chain", () => {
  it("stays verifiably intact after a burst of concurrent writes", async () => {
    const before = await verifyAuditChainIntegrity();
    expect(before).toBe(true);

    // Fire several logAction calls concurrently — this is exactly the
    // shape of race that broke the chain before the advisory-lock fix
    // (multiple detections/timeline entries from one detection run,
    // written back to back).
    await Promise.all(
      Array.from({ length: 8 }, (_, i) => logAction({ action: `audit.test.concurrent.${i}`, detail: { i } })),
    );

    const after = await verifyAuditChainIntegrity();
    expect(after).toBe(true);
  });

  it("produces a chain where each entry's prevHash matches the prior entry's currentHash", async () => {
    // Unique-per-run action name — this dev database persists across test
    // runs (and other test FILES write to this same shared chain
    // concurrently, as separate Vitest worker processes), so this can't
    // assume two of its own logAction calls land back-to-back with
    // nothing else interleaved. Instead it looks up whatever entry
    // actually immediately precedes this one by `seq` (committed order),
    // however many other writers landed in between, and checks the
    // linkage against that.
    const runId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const action = `audit.test.sequence.${runId}`;

    await logAction({ action });

    const entry = await db.auditLog.findFirstOrThrow({ where: { action } });
    const predecessor = await db.auditLog.findFirst({
      where: { seq: { lt: entry.seq } },
      orderBy: { seq: "desc" },
    });

    expect(entry.prevHash).toBe(predecessor?.currentHash ?? "GENESIS");
  });

  it("stays verifiable when `detail` embeds a raw Date (not just an ISO string)", async () => {
    // Real bug: a Date has no own enumerable properties, so canonicalJson's
    // plain-object branch silently serialized it to "{}" at write time —
    // but Postgres's Json column (via Prisma) serializes a Date through
    // .toJSON() into an ISO string, so verifyAuditChainIntegrity's
    // read-time recomputation produced a different hash and broke the
    // chain the moment any caller (e.g. src/lib/pentest.ts's
    // schedulePentestRequest) passed a Date through `detail`.
    const runId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const action = `audit.test.date-detail.${runId}`;

    await logAction({ action, detail: { scheduledAt: new Date("2026-11-01T10:00:00.000Z") } });

    expect(await verifyAuditChainIntegrity()).toBe(true);
  });
});
