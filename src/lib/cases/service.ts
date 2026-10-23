import type { CaseSeverity, CaseStatus, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { CLOSED_STATUSES } from "@/lib/cases/labels";

// Analyst-driven case lifecycle: triage status, assignment, notes. Shared by
// every module's case view.

export async function setCaseStatus(caseId: string, status: CaseStatus, actorId: string, note?: string) {
  const before = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { status: true } });
  const closing = CLOSED_STATUSES.includes(status);
  await db.case.update({
    where: { id: caseId },
    data: { status, resolvedAt: closing ? new Date() : null },
  });
  await db.timelineEntry.create({
    data: {
      caseId,
      occurredAt: new Date(),
      actor: "analyst",
      action: "case.status_changed",
      detail: `${before.status} → ${status}${note ? `: ${note}` : ""}`,
    },
  });
  await logAction({ actorId, caseId, action: "case.status_changed", detail: { from: before.status, to: status, note } });
}

export async function setCaseSeverity(caseId: string, severity: CaseSeverity, actorId: string) {
  const before = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { severity: true } });
  await db.case.update({ where: { id: caseId }, data: { severity } });
  await logAction({ actorId, caseId, action: "case.severity_changed", detail: { from: before.severity, to: severity } });
}

export async function assignCase(caseId: string, assigneeId: string | null, actorId: string) {
  await db.case.update({ where: { id: caseId }, data: { assignedToId: assigneeId } });
  await logAction({ actorId, caseId, action: "case.assigned", detail: { assigneeId } });
}

export async function addCaseNote(caseId: string, note: string, actor: { id: string; name?: string | null }) {
  await db.timelineEntry.create({
    data: {
      caseId,
      occurredAt: new Date(),
      actor: actor.name ?? "analyst",
      action: "analyst.note",
      detail: note,
    },
  });
  await logAction({ actorId: actor.id, caseId, action: "case.note_added", detail: { length: note.length } });
}

export interface CaseListFilters {
  sourceType?: Prisma.CaseWhereInput["sourceType"];
  status?: "open" | "closed" | "all";
  severity?: CaseSeverity;
  technique?: string;
  q?: string;
}

export function caseWhere(filters: CaseListFilters): Prisma.CaseWhereInput {
  const where: Prisma.CaseWhereInput = {};
  if (filters.sourceType) where.sourceType = filters.sourceType;
  if (filters.severity) where.severity = filters.severity;
  // A parent technique also matches cases mapped to its sub-techniques.
  if (filters.technique) {
    where.mitreTechniques = {
      some: { OR: [{ techniqueId: filters.technique }, { techniqueId: { startsWith: `${filters.technique}.` } }] },
    };
  }
  if (filters.status === "open") where.status = { notIn: CLOSED_STATUSES };
  if (filters.status === "closed") where.status = { in: CLOSED_STATUSES };
  if (filters.q) {
    where.OR = [
      { title: { contains: filters.q, mode: "insensitive" } },
      { summary: { contains: filters.q, mode: "insensitive" } },
      { sourceRef: { contains: filters.q, mode: "insensitive" } },
    ];
  }
  return where;
}
