"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { runSimulation } from "@/lib/detection/simulation";
import { ingestRawLog, type RawLog } from "@/lib/detection/ingestion";
import { runDetections } from "@/lib/detection/engine";
import { toNormalizedEvent } from "@/lib/detection/types";
import { requireSession, tenantWhere } from "@/lib/tenant";
import type { EventSource } from "@prisma/client";

export async function runSimulationAction(count: number) {
  const ctx = await requireSession();
  const result = await runSimulation(count, ctx.organizationId);
  revalidatePath("/cases");
  revalidatePath("/");
  return result;
}

export async function ingestLogAction(source: EventSource, raw: RawLog) {
  const ctx = await requireSession();
  await ingestRawLog(source, raw, ctx.organizationId);

  // Note: for a platform role (organizationId null), tenantWhere() is
  // unscoped, so this intentionally processes every tenant's backlog in
  // one run — fine for the platform owner's own demo/test ingestion, but
  // not how a real per-tenant integration should call this (see
  // src/app/api/integrations/[id]/ingest, which always passes a real org id).
  const uncasedEvents = await db.ingestedEvent.findMany({
    where: { caseId: null, ...tenantWhere(ctx) },
    orderBy: { timestamp: "asc" },
  });
  const result = await runDetections(uncasedEvents.map(toNormalizedEvent), ctx.organizationId);

  revalidatePath("/cases");
  revalidatePath("/");
  return result;
}

export async function listCasesAction() {
  const ctx = await requireSession();
  return db.case.findMany({
    where: { sourceType: "SIEM_ALERT", ...tenantWhere(ctx) },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
}

export async function getCaseDetailAction(caseId: string) {
  const ctx = await requireSession();
  return db.case.findUnique({
    where: { id: caseId, ...tenantWhere(ctx) },
    include: {
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: { occurredAt: "asc" } },
    },
  });
}
