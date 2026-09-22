"use server";

import { revalidatePath } from "next/cache";

import { db } from "@/lib/db";
import { runSimulation } from "@/lib/detection/simulation";
import { ingestRawLog, type RawLog } from "@/lib/detection/ingestion";
import { runDetections } from "@/lib/detection/engine";
import { toNormalizedEvent } from "@/lib/detection/types";
import type { EventSource } from "@prisma/client";

export async function runSimulationAction(count: number) {
  const result = await runSimulation(count);
  revalidatePath("/cases");
  revalidatePath("/");
  return result;
}

export async function ingestLogAction(source: EventSource, raw: RawLog) {
  await ingestRawLog(source, raw);

  const uncasedEvents = await db.ingestedEvent.findMany({
    where: { caseId: null },
    orderBy: { timestamp: "asc" },
  });
  const result = await runDetections(uncasedEvents.map(toNormalizedEvent));

  revalidatePath("/cases");
  revalidatePath("/");
  return result;
}

export async function listCasesAction() {
  return db.case.findMany({
    where: { sourceType: "SIEM_ALERT" },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
}

export async function getCaseDetailAction(caseId: string) {
  return db.case.findUnique({
    where: { id: caseId },
    include: {
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: { occurredAt: "asc" } },
    },
  });
}
