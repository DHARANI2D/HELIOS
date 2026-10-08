import { randomBytes } from "node:crypto";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { ingestRawLog, type RawLog } from "@/lib/detection/ingestion";
import { runDetections } from "@/lib/detection/engine";
import { toNormalizedEvent } from "@/lib/detection/types";
import type { IntegrationCategory, EventSource } from "@prisma/client";

// A vendor-agnostic webhook ingestion framework — any tool that can POST
// a webhook (most SIEMs/EDRs/cloud security tools can) points at the URL
// this generates and its events flow straight into the existing
// detection engine. Real pull-based per-vendor API clients (e.g.
// "isolate host via the CrowdStrike API") are deliberately out of scope
// here — this is the extensible interface they'd plug into once there's
// a real vendor credential to build/test against.

type Scope = { organizationId?: string };

function generateWebhookSecret(): string {
  return randomBytes(24).toString("base64url");
}

export async function createIntegration(
  organizationId: string,
  vendorLabel: string,
  category: IntegrationCategory,
  actorId?: string,
) {
  const integration = await db.integration.create({
    data: { organizationId, vendorLabel, category, webhookSecret: generateWebhookSecret() },
  });
  await logAction({
    actorId,
    organizationId,
    action: "integration.created",
    detail: { integrationId: integration.id, vendorLabel, category },
  });
  return integration;
}

export async function listIntegrations(scope: Scope = {}) {
  return db.integration.findMany({ where: scope, orderBy: { createdAt: "desc" } });
}

export async function deleteIntegration(id: string, scope: Scope = {}, actorId?: string) {
  const integration = await db.integration.findFirstOrThrow({ where: { id, ...scope } });
  await db.integration.delete({ where: { id: integration.id } });
  await logAction({
    actorId,
    organizationId: integration.organizationId,
    action: "integration.deleted",
    detail: { integrationId: id, vendorLabel: integration.vendorLabel },
  });
}

export interface IngestPayload {
  source: EventSource;
  events: RawLog[];
}

// Called by the webhook route (src/app/api/integrations/[id]/ingest).
// Validates the bearer secret, normalizes + stores each event scoped to
// the integration's org, then runs the same detection engine every other
// module feeds — a connected third-party tool produces Cases exactly
// like the built-in simulator does.
export async function handleIngest(integrationId: string, secret: string, payload: IngestPayload) {
  const integration = await db.integration.findUnique({ where: { id: integrationId } });
  if (!integration || integration.webhookSecret !== secret) {
    return { ok: false as const, status: 401, error: "Invalid integration or secret" };
  }

  for (const event of payload.events) {
    await ingestRawLog(payload.source, event, integration.organizationId);
  }

  const uncasedEvents = await db.ingestedEvent.findMany({
    where: { caseId: null, organizationId: integration.organizationId },
    orderBy: { timestamp: "asc" },
  });
  const result = await runDetections(uncasedEvents.map(toNormalizedEvent), integration.organizationId);

  await db.integration.update({
    where: { id: integration.id },
    data: { status: "CONNECTED", lastIngestAt: new Date() },
  });

  return { ok: true as const, status: 200, ingestedCount: payload.events.length, ...result };
}
