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
    // Unique-per-run action names — this dev database persists across
    // test runs, so a fixed name would collide with rows from earlier runs.
    const runId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const actionA = `audit.test.sequence.a.${runId}`;
    const actionB = `audit.test.sequence.b.${runId}`;

    await logAction({ action: actionA });
    await logAction({ action: actionB });

    const a = await db.auditLog.findFirstOrThrow({ where: { action: actionA } });
    const b = await db.auditLog.findFirstOrThrow({ where: { action: actionB } });

    expect(b.prevHash).toBe(a.currentHash);
  });
});
