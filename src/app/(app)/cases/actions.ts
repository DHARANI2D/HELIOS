"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import type { CaseSeverity, CaseStatus } from "@prisma/client";

import { db } from "@/lib/db";
import { requireUser } from "@/lib/session";
import { CASE_STATUSES } from "@/lib/cases/labels";
import { addCaseNote, assignCase, setCaseSeverity, setCaseStatus } from "@/lib/cases/service";
import { executePlaybook } from "@/lib/playbooks/engine";
import { logAction } from "@/lib/audit";
import { isTelemetrySource } from "@/lib/siem/adapters";
import { ingestTelemetry, type IngestItem } from "@/lib/siem/service";
import { availableTactics, runSimulation, type SimulationConfig } from "@/lib/siem/simulation";

const MAX_INGEST_EVENTS = 5000;

function revalidateCases(caseId?: string) {
  revalidatePath("/cases");
  revalidatePath("/");
  if (caseId) revalidatePath(`/cases/${caseId}`);
}

export async function listTacticsAction() {
  await requireUser();
  return availableTactics();
}

const simulationSchema = z.object({
  tactics: z.array(z.string()).max(20).optional(),
  count: z.number().int().min(1).max(48).optional(),
  intensity: z.enum(["low", "medium", "high"]).optional(),
});

export async function runSimulationAction(config: SimulationConfig) {
  const user = await requireUser();
  const parsed = simulationSchema.parse(config);
  const result = await runSimulation(parsed, user.id);
  revalidateCases();
  return result;
}

// Accepts either a JSON array of raw logs (all from `source`), a single raw
// log object, JSON Lines, or an array of { source, data } items mixing sources.
function parseIngestPayload(defaultSource: string, text: string): IngestItem[] {
  const trimmed = text.trim();
  if (!trimmed) throw new Error("Paste at least one log entry");

  let records: unknown[];
  try {
    const parsed = JSON.parse(trimmed);
    records = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    records = trimmed.split("\n").filter((l) => l.trim()).map((line, i) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`Line ${i + 1} is not valid JSON`);
      }
    });
  }

  if (records.length > MAX_INGEST_EVENTS) throw new Error(`At most ${MAX_INGEST_EVENTS} events per ingest`);

  return records.map((record, i) => {
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error(`Entry ${i + 1} is not an object`);
    const r = record as Record<string, unknown>;
    if (isTelemetrySource(r.source) && r.data && typeof r.data === "object") {
      return { source: r.source, data: r.data as Record<string, unknown> };
    }
    if (!isTelemetrySource(defaultSource)) throw new Error("Choose a telemetry source");
    return { source: defaultSource, data: r };
  });
}

export async function ingestLogsAction(source: string, text: string) {
  const user = await requireUser();
  const items = parseIngestPayload(source, text);
  const summary = await ingestTelemetry(items, { actorId: user.id, label: "manual ingest" });
  revalidateCases();
  return summary;
}

export async function setCaseStatusAction(caseId: string, status: CaseStatus, note?: string) {
  const user = await requireUser();
  if (!CASE_STATUSES.includes(status)) throw new Error("Invalid status");
  await setCaseStatus(caseId, status, user.id, note?.trim() || undefined);
  revalidateCases(caseId);
}

export async function setCaseSeverityAction(caseId: string, severity: CaseSeverity) {
  const user = await requireUser();
  await setCaseSeverity(caseId, z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).parse(severity), user.id);
  revalidateCases(caseId);
}

export async function assignCaseAction(caseId: string, assignToMe: boolean) {
  const user = await requireUser();
  await assignCase(caseId, assignToMe ? user.id : null, user.id);
  revalidateCases(caseId);
}

export async function addCaseNoteAction(caseId: string, note: string) {
  const user = await requireUser();
  const text = note.trim();
  if (!text) throw new Error("Note is empty");
  if (text.length > 5000) throw new Error("Note is too long");
  await addCaseNote(caseId, text, user);
  revalidateCases(caseId);
}

// Analyst-initiated run. Playbooks flagged requireApproval still go through
// the approval queue — starting one manually doesn't bypass the gate.
export async function runPlaybookOnCaseAction(caseId: string, playbookId: string) {
  const user = await requireUser();
  const playbook = await db.playbook.findUniqueOrThrow({ where: { id: playbookId } });

  if (playbook.requireApproval) {
    const execution = await db.playbookExecution.create({
      data: { playbookId, caseId, status: "PENDING_APPROVAL", triggeredBy: "manual" },
    });
    await db.case.updateMany({
      where: { id: caseId, status: { notIn: ["RESOLVED", "FALSE_POSITIVE", "CONTAINED"] } },
      data: { status: "AWAITING_APPROVAL" },
    });
    await logAction({ actorId: user.id, caseId, action: "playbook.approval_requested", detail: { playbookId, executionId: execution.id, manual: true } });
    revalidateCases(caseId);
    return { queued: true };
  }

  await executePlaybook({ playbookId, caseId, triggeredBy: "manual", actorId: user.id });
  revalidateCases(caseId);
  return { queued: false };
}
