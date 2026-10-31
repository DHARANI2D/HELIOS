import type { CaseDisposition, CaseSeverity, CaseStatus, Prisma, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { CLOSED_STATUSES } from "@/lib/cases/labels";

// Analyst-driven case lifecycle: triage status and severity, plus the list
// filters. Assignment, comments and escalation live in lib/cases/collab.

export const DISPOSITIONS: CaseDisposition[] = ["TRUE_POSITIVE", "BENIGN_TRUE_POSITIVE", "FALSE_POSITIVE"];

// Closing a case takes the analyst's disposition and why: the ground truth
// AI decisions are scored against (lib/shadow). "False positive" as a status
// implies the disposition; the reason can come from the note.
export async function setCaseStatus(caseId: string, status: CaseStatus, actorId: string, note?: string, close?: { disposition?: CaseDisposition | null; reason?: string | null }) {
  const before = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { status: true, acknowledgedAt: true } });
  const closing = CLOSED_STATUSES.includes(status);
  const disposition = closing ? (close?.disposition ?? (status === "FALSE_POSITIVE" ? "FALSE_POSITIVE" : null)) : null;
  const reason = (close?.reason ?? note ?? "").trim();
  if (closing && !disposition) throw new Error("Choose a disposition to close the case: true positive, benign true positive or false positive");
  if (closing && reason.length < 3) throw new Error("Say why (the reason is kept with the disposition)");
  if (status === "FALSE_POSITIVE" && disposition !== "FALSE_POSITIVE") throw new Error("A case closed as a false positive has that disposition");
  if (closing && disposition === "TRUE_POSITIVE") {
    const { openRequiredSteps } = await import("@/lib/runbooks/service");
    const open = await openRequiredSteps(caseId);
    if (open.length) throw new Error(`Finish or skip (with a reason) the required runbook steps first: ${open.map((r) => `${r.title}: ${r.steps.join("; ")}`).join(" · ")}`);
  }
  // The first human status change counts as acknowledgement.
  await db.case.update({
    where: { id: caseId },
    data: {
      status,
      resolvedAt: closing ? new Date() : null,
      ...(before.acknowledgedAt ? {} : { acknowledgedAt: new Date() }),
      ...(closing ? { disposition, dispositionReason: reason, dispositionById: actorId, dispositionAt: new Date() } : { disposition: null, dispositionReason: null, dispositionById: null, dispositionAt: null }),
    },
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
  await logAction({ actorId, caseId, action: "case.status_changed", detail: { from: before.status, to: status, note, ...(closing ? { disposition, reason } : {}) } });
  // Score the AI against the analyst's call (or clear the scores on reopen).
  const { scoreClosedCase } = await import("@/lib/shadow/service");
  await scoreClosedCase(caseId);
}

export async function setCaseSeverity(caseId: string, severity: CaseSeverity, actorId: string) {
  const before = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { severity: true } });
  await db.case.update({ where: { id: caseId }, data: { severity } });
  await logAction({ actorId, caseId, action: "case.severity_changed", detail: { from: before.severity, to: severity } });
}

export type CaseQueue = "mine" | "unassigned" | "approval" | "sla" | "ai" | "tier3";

export interface CaseListFilters {
  sourceType?: Prisma.CaseWhereInput["sourceType"];
  status?: "open" | "closed" | "all";
  severity?: CaseSeverity;
  technique?: string;
  q?: string;
  domain?: SecurityDomain;
  queue?: CaseQueue;
  viewerId?: string;
  now?: Date;
}

export function caseWhere(filters: CaseListFilters): Prisma.CaseWhereInput {
  const where: Prisma.CaseWhereInput = {};
  if (filters.domain) where.domain = filters.domain;
  switch (filters.queue) {
    case "mine":
      where.assignedToId = filters.viewerId ?? "__none__";
      break;
    case "unassigned":
      where.assignedToId = null;
      break;
    case "approval":
      where.status = "AWAITING_APPROVAL";
      break;
    case "sla":
      where.acknowledgedAt = null;
      where.slaDueAt = { lte: new Date((filters.now ?? new Date()).getTime() + 30 * 60_000) };
      break;
    case "ai":
      where.aiStatus = "completed";
      where.acknowledgedAt = null;
      break;
    case "tier3":
      where.tier = 3;
      break;
  }
  if (filters.sourceType) where.sourceType = filters.sourceType;
  if (filters.severity) where.severity = filters.severity;
  // A parent technique also matches cases mapped to its sub-techniques.
  if (filters.technique) {
    where.mitreTechniques = {
      some: { OR: [{ techniqueId: filters.technique }, { techniqueId: { startsWith: `${filters.technique}.` } }] },
    };
  }
  if (filters.queue !== "approval") {
    if (filters.status === "open") where.status = { notIn: CLOSED_STATUSES };
    if (filters.status === "closed") where.status = { in: CLOSED_STATUSES };
  }
  if (filters.q) {
    where.OR = [
      { title: { contains: filters.q, mode: "insensitive" } },
      { summary: { contains: filters.q, mode: "insensitive" } },
      { sourceRef: { contains: filters.q, mode: "insensitive" } },
    ];
  }
  return where;
}
