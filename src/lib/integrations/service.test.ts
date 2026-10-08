import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";

import { createIntegration, handleIngest } from "./service";
import { db } from "@/lib/db";

// Integration test against the real Postgres instance (same rationale as
// src/lib/audit.test.ts and src/lib/pentest.test.ts) — the thing worth
// verifying here is specifically the auth boundary: a webhook payload
// must never be accepted without the right per-integration secret.

describe("integrations webhook ingest auth", () => {
  let organizationId: string;
  let integrationId: string;
  let webhookSecret: string;
  const createdEventIds: string[] = [];
  const createdCaseIds: string[] = [];

  beforeAll(async () => {
    const org = await db.organization.findUniqueOrThrow({ where: { slug: "acme-demo" } });
    organizationId = org.id;
    const integration = await createIntegration(organizationId, "Vitest Test Tool", "SIEM");
    integrationId = integration.id;
    webhookSecret = integration.webhookSecret;
  });

  afterEach(async () => {
    // Does NOT delete any Case a detection may have produced — see
    // src/lib/pentest.test.ts's afterAll comment: Case is referenced by
    // AuditLog.caseId with onDelete: Restrict specifically so this kind
    // of cleanup can't silently corrupt an audit entry's hash. Detections/
    // timeline entries aren't audit-referenced, so those are still safe
    // to remove.
    for (const caseId of createdCaseIds.splice(0)) {
      await db.timelineEntry.deleteMany({ where: { caseId } });
      await db.detection.deleteMany({ where: { caseId } });
    }
    for (const id of createdEventIds.splice(0)) {
      await db.ingestedEvent.delete({ where: { id } }).catch(() => {});
    }
  });

  afterAll(async () => {
    await db.integration.delete({ where: { id: integrationId } }).catch(() => {});
  });

  it("rejects a missing/wrong secret with ok:false and never writes an event", async () => {
    const before = await db.ingestedEvent.count({ where: { organizationId } });

    const wrongSecret = await handleIngest(integrationId, "not-the-real-secret", {
      source: "AUTH",
      events: [{ user: "attacker", result: "SUCCESS" }],
    });
    expect(wrongSecret.ok).toBe(false);
    if (!wrongSecret.ok) expect(wrongSecret.status).toBe(401);

    const afterCount = await db.ingestedEvent.count({ where: { organizationId } });
    expect(afterCount).toBe(before);
  });

  it("rejects an unknown integration id the same way", async () => {
    const result = await handleIngest("not-a-real-integration-id", webhookSecret, {
      source: "AUTH",
      events: [],
    });
    expect(result.ok).toBe(false);
  });

  it("accepts the right secret, stores the event scoped to the integration's org, and marks the integration connected", async () => {
    const result = await handleIngest(integrationId, webhookSecret, {
      source: "AUTH",
      events: [{ user: "vitest-user", result: "FAILED", source_ip: "203.0.113.5" }],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.ingestedCount).toBe(1);

    const event = await db.ingestedEvent.findFirstOrThrow({
      where: { organizationId, actorUser: "vitest-user" },
    });
    createdEventIds.push(event.id);
    if (event.caseId) createdCaseIds.push(event.caseId);
    expect(event.organizationId).toBe(organizationId);

    const integration = await db.integration.findUniqueOrThrow({ where: { id: integrationId } });
    expect(integration.status).toBe("CONNECTED");
    expect(integration.lastIngestAt).not.toBeNull();
  });
});
