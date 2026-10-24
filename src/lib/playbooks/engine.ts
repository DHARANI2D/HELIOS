import type { Case, PlaybookExecution } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { matchesTrigger, parseTrigger, type CaseSnapshot } from "@/lib/playbooks/trigger";
import { CONTAINMENT_ACTIONS, buildActionContext, executeAction, paramsOf, type ActionResult } from "@/lib/response/executor";

// Ported from signal-fusion's services/playbookEngine.ts and generalized from
// Alert to the unified Case. Execution state lives in PlaybookExecution;
// approvals in PlaybookApproval; every step lands on the case timeline and
// in the audit log.

const CLOSED_STATUSES = new Set(["RESOLVED", "FALSE_POSITIVE"]);

export async function loadCaseSnapshot(caseId: string): Promise<(CaseSnapshot & { case: Case }) | null> {
  const kase = await db.case.findUnique({
    where: { id: caseId },
    include: {
      mitreTechniques: { select: { techniqueId: true } },
      detections: { select: { source: true } },
    },
  });
  if (!kase) return null;
  return {
    case: kase,
    severity: kase.severity,
    sourceType: kase.sourceType,
    techniqueIds: kase.mitreTechniques.map((t) => t.techniqueId),
    detectionSources: [...new Set(kase.detections.map((d) => d.source))],
    riskScore: kase.riskScore,
    verdict: kase.verdict,
  };
}

export async function findMatchingPlaybooks(caseId: string) {
  const snapshot = await loadCaseSnapshot(caseId);
  if (!snapshot) return [];
  const playbooks = await db.playbook.findMany({
    where: { enabled: true },
    include: { actions: { orderBy: { order: "asc" } } },
    orderBy: { priority: "desc" },
  });
  return playbooks.filter((pb) => {
    const trigger = parseTrigger(pb.triggerCondition);
    return trigger !== null && matchesTrigger(trigger, snapshot);
  });
}

// Called by the case writer whenever a case is created or gains new
// evidence. Each playbook fires at most once per case.
export async function evaluatePlaybooksForCase(caseId: string) {
  const snapshot = await loadCaseSnapshot(caseId);
  if (!snapshot || CLOSED_STATUSES.has(snapshot.case.status)) return [];

  const matched = await findMatchingPlaybooks(caseId);
  const fired: PlaybookExecution[] = [];

  for (const playbook of matched) {
    if (!playbook.requireApproval && !playbook.autoExecute) continue; // manual-only: surfaced as a suggestion
    const already = await db.playbookExecution.findFirst({
      where: { playbookId: playbook.id, caseId },
      select: { id: true },
    });
    if (already) continue;

    if (playbook.requireApproval) {
      const execution = await db.playbookExecution.create({
        data: { playbookId: playbook.id, caseId, status: "PENDING_APPROVAL", triggeredBy: "auto" },
      });
      await db.case.updateMany({
        where: { id: caseId, status: { notIn: ["RESOLVED", "FALSE_POSITIVE", "CONTAINED"] } },
        data: { status: "AWAITING_APPROVAL" },
      });
      await db.timelineEntry.create({
        data: {
          caseId,
          occurredAt: new Date(),
          actor: "playbook-engine",
          action: "playbook.approval_requested",
          detail: `"${playbook.name}" matched and is awaiting analyst approval`,
        },
      });
      await logAction({
        caseId,
        action: "playbook.approval_requested",
        detail: { playbookId: playbook.id, executionId: execution.id },
      });
      fired.push(execution);
    } else {
      fired.push(await executePlaybook({ playbookId: playbook.id, caseId, triggeredBy: "auto" }));
    }
  }
  return fired;
}

interface ExecuteInput {
  playbookId: string;
  caseId: string;
  triggeredBy: "auto" | "manual" | "retroactive";
  actorId?: string;
  executionId?: string; // resume an approved PENDING_APPROVAL execution
}

export async function executePlaybook({ playbookId, caseId, triggeredBy, actorId, executionId }: ExecuteInput) {
  const playbook = await db.playbook.findUniqueOrThrow({
    where: { id: playbookId },
    include: { actions: { orderBy: { order: "asc" } } },
  });
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId } });

  const execution = executionId
    ? await db.playbookExecution.update({
        where: { id: executionId },
        data: { status: "RUNNING", startedAt: new Date() },
      })
    : await db.playbookExecution.create({
        data: { playbookId, caseId, status: "RUNNING", triggeredBy },
      });

  const context = await buildActionContext(kase);
  const results: ActionResult[] = [];
  let failure: string | null = null;

  for (const action of playbook.actions) {
    try {
      const result = await executeAction({ name: action.name, actionType: action.actionType, params: paramsOf(action.parameters) }, kase, context, `playbook:${playbook.name}`);
      results.push(result);
      await db.timelineEntry.create({
        data: {
          caseId,
          occurredAt: new Date(),
          actor: `playbook:${playbook.name}`,
          action: `playbook.${action.actionType.toLowerCase()}`,
          detail: `${action.name}: ${result.summary}`,
          evidence: result as never,
        },
      });
    } catch (err) {
      failure = err instanceof Error ? err.message : String(err);
      results.push({ action: action.name, actionType: action.actionType, status: "failed", summary: failure });
      break;
    }
  }

  const finished = await db.playbookExecution.update({
    where: { id: execution.id },
    data: {
      status: failure ? "FAILED" : "SUCCEEDED",
      results: results as never,
      error: failure,
      finishedAt: new Date(),
    },
  });

  const contained = !failure && results.some((r) => CONTAINMENT_ACTIONS.has(r.actionType as never) && r.status === "succeeded" && !r.skipped);
  if (contained && !CLOSED_STATUSES.has(kase.status)) {
    await db.case.update({ where: { id: caseId }, data: { status: "CONTAINED", containedAt: kase.containedAt ?? new Date() } });
  } else if (kase.status === "AWAITING_APPROVAL") {
    const stillPending = await db.playbookExecution.count({ where: { caseId, status: "PENDING_APPROVAL" } });
    if (stillPending === 0) await db.case.update({ where: { id: caseId }, data: { status: "INVESTIGATING" } });
  }

  await logAction({
    actorId,
    caseId,
    action: failure ? "playbook.failed" : "playbook.executed",
    detail: { playbookId, executionId: execution.id, triggeredBy, results, error: failure },
  });

  return finished;
}

export async function decideExecution(executionId: string, decision: "approved" | "rejected", approverId: string, notes?: string) {
  const execution = await db.playbookExecution.findUniqueOrThrow({ where: { id: executionId } });
  if (execution.status !== "PENDING_APPROVAL") throw new Error("Execution is not awaiting approval");

  await db.playbookApproval.create({ data: { executionId, approverId, decision, notes } });

  if (decision === "approved") {
    return executePlaybook({
      playbookId: execution.playbookId,
      caseId: execution.caseId,
      triggeredBy: execution.triggeredBy as ExecuteInput["triggeredBy"],
      actorId: approverId,
      executionId,
    });
  }

  const rejected = await db.playbookExecution.update({
    where: { id: executionId },
    data: { status: "REJECTED", finishedAt: new Date() },
  });
  const stillPending = await db.playbookExecution.count({ where: { caseId: execution.caseId, status: "PENDING_APPROVAL" } });
  if (stillPending === 0) {
    await db.case.updateMany({
      where: { id: execution.caseId, status: "AWAITING_APPROVAL" },
      data: { status: "INVESTIGATING" },
    });
  }
  await logAction({
    actorId: approverId,
    caseId: execution.caseId,
    action: "playbook.rejected",
    detail: { executionId, notes },
  });
  return rejected;
}

// Signal-fusion's executeRetroactive: apply a playbook to existing open cases
// (most recent 100) that match its trigger and haven't run it yet.
export async function runRetroactive(playbookId: string, actorId?: string) {
  const playbook = await db.playbook.findUniqueOrThrow({ where: { id: playbookId } });
  const trigger = parseTrigger(playbook.triggerCondition);
  if (!trigger) throw new Error("Playbook trigger is invalid");

  const cases = await db.case.findMany({
    where: { status: { notIn: ["RESOLVED", "FALSE_POSITIVE"] }, playbookRuns: { none: { playbookId } } },
    orderBy: { createdAt: "desc" },
    take: 100,
    select: { id: true },
  });

  let matched = 0;
  let queued = 0;
  for (const { id } of cases) {
    const snapshot = await loadCaseSnapshot(id);
    if (!snapshot || !matchesTrigger(trigger, snapshot)) continue;
    matched++;
    if (playbook.requireApproval) {
      await db.playbookExecution.create({
        data: { playbookId, caseId: id, status: "PENDING_APPROVAL", triggeredBy: "retroactive" },
      });
      await db.case.updateMany({
        where: { id, status: { notIn: ["RESOLVED", "FALSE_POSITIVE", "CONTAINED"] } },
        data: { status: "AWAITING_APPROVAL" },
      });
      queued++;
    } else {
      await executePlaybook({ playbookId, caseId: id, triggeredBy: "retroactive", actorId });
    }
  }

  await logAction({
    actorId,
    action: "playbook.retroactive_run",
    detail: { playbookId, analyzed: cases.length, matched, queuedForApproval: queued },
  });
  return { analyzed: cases.length, matched, queuedForApproval: queued };
}

export type { ActionResult };
