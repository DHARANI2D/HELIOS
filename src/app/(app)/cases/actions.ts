"use server";

import { after } from "next/server";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import type { CaseDisposition, CaseSeverity, CaseStatus, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { requirePermission, type SessionUser } from "@/lib/session";
import { can, type Permission } from "@/lib/rbac";
import { assertCaseAccess } from "@/lib/access";
import { resolveTenantInput } from "@/lib/tenants";
import { CASE_STATUSES } from "@/lib/cases/labels";
import { DISPOSITIONS, setCaseSeverity, setCaseStatus } from "@/lib/cases/service";
import { acknowledgeCase, addComment, assignCaseTo, escalateCase, publishReport, setWatching, shareCase } from "@/lib/cases/collab";
import { executePlaybook } from "@/lib/playbooks/engine";
import { logAction } from "@/lib/audit";
import { isTelemetrySource } from "@/lib/siem/adapters";
import { ingestTelemetry, type IngestItem } from "@/lib/siem/service";
import { DISPATCHABLE_AGENTS, type AgentKey } from "@/lib/ai/catalog";
import { runAgentOnCase } from "@/lib/ai/first-response";
import { PROPOSABLE_ACTIONS } from "@/lib/ai/triage";
import { completeManualAction, decideResponseAction, requestAnalystAction, rollbackResponseAction } from "@/lib/response/service";

const MAX_INGEST_EVENTS = 5000;

function revalidateCases(caseId?: string) {
  revalidatePath("/cases");
  revalidatePath("/");
  if (caseId) revalidatePath(`/cases/${caseId}`);
}

// Every case mutation: the permission, then the row-level check (client
// tenant, analyst queues) — out-of-scope ids look like missing cases.
async function caseActor(caseId: string, ...permissions: Permission[]): Promise<SessionUser> {
  const user = await requirePermission(...permissions);
  await assertCaseAccess(user, caseId);
  return user;
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

export async function ingestLogsAction(source: string, text: string, tenantId?: string) {
  const user = await requirePermission("telemetry.ingest");
  const items = parseIngestPayload(source, text);
  const summary = await ingestTelemetry(items, { actorId: user.id, label: "manual ingest", tenantId: await resolveTenantInput(user, tenantId) });
  revalidateCases();
  return summary;
}

// --- triage --------------------------------------------------------------

export async function setCaseStatusAction(caseId: string, status: CaseStatus, note?: string, close?: { disposition?: string | null; reason?: string | null }) {
  const user = await caseActor(caseId, "cases.triage");
  if (!CASE_STATUSES.includes(status)) throw new Error("Invalid status");
  const disposition = close?.disposition ? z.enum(DISPOSITIONS as [CaseDisposition, ...CaseDisposition[]]).parse(close.disposition) : null;
  await setCaseStatus(caseId, status, user.id, note?.trim() || undefined, { disposition, reason: close?.reason?.trim().slice(0, 2000) ?? null });
  revalidateCases(caseId);
}

export async function setCaseSeverityAction(caseId: string, severity: CaseSeverity) {
  const user = await caseActor(caseId, "cases.triage");
  await setCaseSeverity(caseId, z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).parse(severity), user.id);
  revalidateCases(caseId);
}

export async function acknowledgeCaseAction(caseId: string) {
  const user = await caseActor(caseId, "cases.triage");
  await acknowledgeCase(caseId, user);
  revalidateCases(caseId);
}

// Assigning yourself needs triage rights; assigning someone else needs cases.assign.
export async function assignCaseAction(caseId: string, assigneeId: string | null) {
  const user = await caseActor(caseId, "cases.triage");
  if (assigneeId && assigneeId !== user.id && !can(user, "cases.assign")) throw new Error("Forbidden: requires cases.assign");
  await assignCaseTo(caseId, assigneeId, user);
  revalidateCases(caseId);
}

export async function setWatchingAction(caseId: string, watching: boolean) {
  const user = await caseActor(caseId, "cases.view");
  await setWatching(caseId, user.id, watching);
  revalidatePath(`/cases/${caseId}`);
}

const commentSchema = z.object({
  body: z.string().trim().min(1, "Comment is empty").max(5000),
  internal: z.boolean(),
  mentions: z.array(z.string()).max(20),
});

export async function addCommentAction(caseId: string, input: z.input<typeof commentSchema>) {
  const user = await caseActor(caseId, "cases.comment");
  await addComment(caseId, user, commentSchema.parse(input));
  revalidatePath(`/cases/${caseId}`);
}

export async function escalateCaseAction(caseId: string, input: { tier: number; assigneeId?: string | null; note?: string }) {
  const user = await caseActor(caseId, "cases.escalate");
  if (input.assigneeId && input.assigneeId !== user.id && !can(user, "cases.assign")) throw new Error("Forbidden: requires cases.assign");
  await escalateCase(caseId, user, { tier: z.number().int().min(1).max(3).parse(input.tier), assigneeId: input.assigneeId, note: input.note?.trim().slice(0, 2000) || undefined });
  revalidateCases(caseId);
}

export async function shareCaseAction(caseId: string, input: { target: "teammates" | "client" | "chat"; userIds?: string[]; note?: string }) {
  const user = await caseActor(caseId, input.target === "teammates" ? "cases.comment" : "cases.share");
  const summary = await shareCase(caseId, user, { target: z.enum(["teammates", "client", "chat"]).parse(input.target), userIds: input.userIds, note: input.note?.slice(0, 2000) });
  revalidatePath(`/cases/${caseId}`);
  return summary;
}

export async function publishReportAction(caseId: string, commentId: string) {
  const user = await caseActor(caseId, "cases.share");
  await publishReport(caseId, commentId, user);
  revalidatePath(`/cases/${caseId}`);
}

// --- AI agents -----------------------------------------------------------

export async function dispatchAgentAction(caseId: string, agentKey: string) {
  const user = await caseActor(caseId, "ai.dispatch");
  if (!DISPATCHABLE_AGENTS.includes(agentKey as AgentKey)) throw new Error("Unknown agent");
  await db.case.update({ where: { id: caseId }, data: { aiStatus: "queued" } });
  await logAction({ actorId: user.id, caseId, action: "ai.dispatched", detail: { agent: agentKey } });
  // A model call can take a while; the case page polls aiStatus.
  after(() => runAgentOnCase(caseId, agentKey as AgentKey, { trigger: "manual", requestedBy: { id: user.id, name: user.name ?? "analyst" } }).catch((err) => console.error("agent dispatch failed", err)));
  revalidatePath(`/cases/${caseId}`);
}

export async function aiStatusAction(caseId: string) {
  await caseActor(caseId, "cases.view");
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { aiStatus: true } });
  return kase.aiStatus;
}

export async function aiFeedbackAction(runId: string, feedback: "agree" | "disagree", note?: string) {
  const run = await db.aiRun.findUniqueOrThrow({ where: { id: runId }, select: { caseId: true } });
  if (!run.caseId) throw new Error("Run is not tied to a case");
  const user = await caseActor(run.caseId, "ai.feedback");
  await db.aiRun.update({ where: { id: runId }, data: { feedback: z.enum(["agree", "disagree"]).parse(feedback), feedbackNote: note?.trim().slice(0, 1000) || null, feedbackById: user.id } });
  await logAction({ actorId: user.id, caseId: run.caseId, action: "ai.feedback", detail: { runId, feedback, note } });
  revalidatePath(`/cases/${run.caseId}`);
}

// --- response actions ----------------------------------------------------

const REQUESTABLE = [...PROPOSABLE_ACTIONS] as [PlaybookActionType, ...PlaybookActionType[]];

export async function requestResponseAction(caseId: string, input: { actionType: string; target: string; rationale?: string }) {
  const user = await caseActor(caseId, "containment.request");
  const actionType = z.enum(REQUESTABLE).parse(input.actionType);
  const target = z.string().trim().min(1).max(300).parse(input.target);
  const canApprove = can(user, "containment.approve") || (actionType === "ISOLATE_HOST" && can(user, "endpoints.contain"));
  const result = await requestAnalystAction({ caseId, actionType, target, rationale: input.rationale?.trim().slice(0, 1000), actor: { id: user.id, name: user.name ?? "analyst" }, canApprove });
  revalidateCases(caseId);
  return { status: result.status };
}

export async function decideResponseActionAction(actionId: string, decision: "approved" | "rejected", note?: string) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId }, select: { caseId: true } });
  const user = await caseActor(action.caseId, "containment.approve");
  const result = await decideResponseAction(actionId, z.enum(["approved", "rejected"]).parse(decision), { id: user.id, name: user.name ?? "approver" }, note?.trim().slice(0, 1000));
  revalidateCases(action.caseId);
  return { status: result.status };
}

export async function rollbackResponseActionAction(actionId: string) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId }, select: { caseId: true } });
  const user = await caseActor(action.caseId, "containment.approve");
  const result = await rollbackResponseAction(actionId, { id: user.id, name: user.name ?? "analyst" });
  revalidateCases(action.caseId);
  return { status: result.status };
}

// Keep a time-boxed action longer (hours), or for good (0).
export async function extendResponseActionAction(actionId: string, hours: number) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId }, select: { caseId: true } });
  const user = await caseActor(action.caseId, "containment.approve");
  const { extendAction } = await import("@/lib/connectors/safety");
  const expiresAt = await extendAction(actionId, z.number().int().min(0).max(24 * 30).parse(hours), { id: user.id, name: user.name ?? "analyst" });
  revalidateCases(action.caseId);
  return { expiresAt: expiresAt?.toISOString() ?? null };
}

// The analyst carried out a MANUAL_REQUIRED action by hand and says so.
export async function completeManualActionAction(actionId: string, note: string) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId }, select: { caseId: true } });
  const user = await caseActor(action.caseId, "containment.approve");
  const result = await completeManualAction(actionId, { id: user.id, name: user.name ?? user.email ?? "analyst" }, z.string().max(1000).parse(note));
  revalidateCases(action.caseId);
  revalidatePath("/endpoints");
  return { status: result.status };
}

// Analyst-initiated run. Playbooks flagged requireApproval still go through
// the approval queue — starting one manually doesn't bypass the gate.
export async function runPlaybookOnCaseAction(caseId: string, playbookId: string) {
  const user = await caseActor(caseId, "containment.request");
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
