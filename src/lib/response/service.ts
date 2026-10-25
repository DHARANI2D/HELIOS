import type { PlaybookActionType, ResponseActionStatus } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import type { PolicyDecision } from "@/lib/response/policy";
import { humanRulebookGate } from "@/lib/rulebook/service";
import { ACTION_LABEL, CONTAINMENT_ACTIONS, ROLLBACK_OF, buildActionContext, executeAction, setEndpointIsolation, type ActionResult } from "@/lib/response/executor";

// Lifecycle of individual response actions (ResponseAction rows): proposed by
// an AI agent or requested by an analyst, approved or rejected by a human
// with containment.approve, executed through the shared executor — or, where
// the client has no response connector, left MANUAL_REQUIRED until an
// analyst carries it out and marks it done — and rolled back when
// containment turns out to be unnecessary. Only EXECUTED containment counts
// towards a case being contained.

const CLOSED = ["RESOLVED", "FALSE_POSITIVE"];

const PARAM_FOR: Partial<Record<PlaybookActionType, string>> = {
  ISOLATE_HOST: "host",
  RELEASE_HOST: "host",
  COLLECT_LOGS: "host",
  BLOCK_IP: "ip",
  UNBLOCK_IP: "ip",
  DISABLE_USER: "user",
  ENABLE_USER: "user",
  KILL_PROCESS: "process",
  QUARANTINE_FILE: "hash",
  BLOCK_SENDER: "sender",
  REVOKE_AGENT: "agentId",
  RESTORE_AGENT: "agentId",
};

export interface Actor {
  id?: string;
  name: string;
}

interface ApprovalMark {
  id: string;
  name: string;
  at: string;
}

export function approvalsOf(value: unknown): ApprovalMark[] {
  return Array.isArray(value) ? value.filter((a): a is ApprovalMark => !!a && typeof a === "object" && typeof (a as ApprovalMark).id === "string") : [];
}

export async function approversFor(caseId: string) {
  const kase = await db.case.findUnique({ where: { id: caseId }, select: { domain: true, tenantId: true } });
  if (!kase) return [];
  const [staff, clientAdmins] = await Promise.all([
    staffFor(["INCIDENT_RESPONDER", "SOC_MANAGER"], kase.domain),
    kase.tenantId ? db.user.findMany({ where: { tenantId: kase.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } }) : Promise.resolve([]),
  ]);
  return [...staff, ...clientAdmins.map((u) => u.id)];
}

export async function recordResponseAction(input: {
  caseId: string;
  actionType: PlaybookActionType;
  target: string | null;
  source: "ai" | "analyst";
  status: ResponseActionStatus;
  rationale?: string | null;
  confidence?: number | null;
  policyReason?: string | null;
  aiRunId?: string | null;
  requestedById?: string | null;
  parameters?: Record<string, string>;
  // The policy decision behind it: rulebook version, trace, approvals needed.
  decision?: Pick<PolicyDecision, "trace" | "approvals" | "policyVersion" | "policyHash">;
}) {
  const { decision, ...data } = input;
  const kase = await db.case.findUniqueOrThrow({ where: { id: input.caseId }, select: { tenantId: true } });
  return db.responseAction.create({
    data: {
      ...data,
      tenantId: kase.tenantId,
      ...(decision
        ? { trace: JSON.parse(JSON.stringify(decision.trace)), requiredApprovals: decision.approvals, policyVersion: decision.policyVersion, policyHash: decision.policyHash }
        : {}),
    },
  });
}

async function markCaseAfterResponse(caseId: string) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { status: true, containedAt: true } });
  if (CLOSED.includes(kase.status)) return;
  const [contained, pending] = await Promise.all([
    db.responseAction.count({ where: { caseId, status: "EXECUTED", actionType: { in: [...CONTAINMENT_ACTIONS] } } }),
    db.responseAction.count({ where: { caseId, status: "PENDING_APPROVAL" } }),
  ]);
  const pendingPlaybooks = await db.playbookExecution.count({ where: { caseId, status: "PENDING_APPROVAL" } });
  if (contained > 0 && kase.status !== "CONTAINED") {
    await db.case.update({ where: { id: caseId }, data: { status: "CONTAINED", containedAt: kase.containedAt ?? new Date() } });
  } else if (contained === 0 && (pending > 0 || pendingPlaybooks > 0) && kase.status !== "AWAITING_APPROVAL") {
    await db.case.update({ where: { id: caseId }, data: { status: "AWAITING_APPROVAL" } });
  } else if (pending === 0 && pendingPlaybooks === 0 && kase.status === "AWAITING_APPROVAL") {
    await db.case.update({ where: { id: caseId }, data: { status: "INVESTIGATING" } });
  }
}

// Runs an action that's been cleared (by policy or by a human).
export async function performResponseAction(actionId: string, actor: Actor) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  const kase = await db.case.findUniqueOrThrow({ where: { id: action.caseId } });
  const ctx = await buildActionContext(kase);
  const paramKey = PARAM_FOR[action.actionType];
  const params: Record<string, string | undefined> = paramKey && action.target ? { [paramKey]: action.target } : {};
  if ((action.actionType === "REVOKE_AGENT" || action.actionType === "RESTORE_AGENT") && kase.sourceType === "AGENT_GOVERNANCE") {
    params.agentId = kase.sourceRef ?? undefined;
  }

  let result: ActionResult;
  try {
    const approvals = Math.max(1, approvalsOf(action.approvals).length);
    result = await executeAction({ name: ACTION_LABEL[action.actionType], actionType: action.actionType, params, approvals, requestId: action.id }, kase, ctx, actor.name);
  } catch (err) {
    result = { action: ACTION_LABEL[action.actionType], actionType: action.actionType, status: "failed", summary: err instanceof Error ? err.message : String(err) };
  }
  // A rulebook refusal at the moment of acting (the rules may have changed
  // while it waited for approval) blocks it rather than failing it.
  const status: ResponseActionStatus = result.blocked
    ? "BLOCKED"
    : result.status === "succeeded"
      ? "EXECUTED"
      : result.status === "manual"
        ? "MANUAL_REQUIRED"
        : result.status === "pending"
          ? "IN_PROGRESS"
          : "FAILED";
  const updated = await db.responseAction.update({
    where: { id: actionId },
    data: { status, result: JSON.parse(JSON.stringify(result)), ...(result.blocked ? { policyReason: result.summary } : {}) },
  });

  await db.timelineEntry.create({
    data: {
      caseId: kase.id,
      occurredAt: new Date(),
      actor: actor.name,
      action: `response.${action.actionType.toLowerCase()}`,
      detail: result.summary,
      evidence: { responseActionId: actionId, source: action.source },
    },
  });
  await logAction({
    actorId: actor.id,
    caseId: kase.id,
    action: status === "EXECUTED" ? "response.executed" : status === "MANUAL_REQUIRED" ? "response.manual_required" : status === "BLOCKED" ? "response.blocked" : status === "IN_PROGRESS" ? "response.requested_from_vendor" : "response.failed",
    detail: { responseActionId: actionId, actionType: action.actionType, target: action.target, source: action.source, summary: result.summary },
  });
  if (status === "EXECUTED") await completeRollbackOf(action.parameters);
  if (status === "EXECUTED" || status === "FAILED") {
    const { afterConnectorOutcome } = await import("@/lib/connectors/safety");
    await afterConnectorOutcome(updated, status);
  }
  if (status === "MANUAL_REQUIRED") {
    await notify(await approversFor(kase.id), {
      kind: "approval",
      title: `Carry out by hand: ${ACTION_LABEL[action.actionType]}${action.target ? ` ${action.target}` : ""}`,
      body: "No response connector can do this for the client. Do it in the tool's console, then mark it done on the case.",
      caseId: kase.id,
      actorName: actor.name,
    }, { exclude: actor.id });
  }
  await markCaseAfterResponse(kase.id);
  return updated;
}

// A rollback that has actually happened retires the action it undoes.
async function completeRollbackOf(parameters: unknown) {
  const original = parameters && typeof parameters === "object" ? (parameters as Record<string, unknown>).rollbackOf : undefined;
  if (typeof original !== "string") return;
  const orig = await db.responseAction.findUnique({ where: { id: original } });
  if (!orig || orig.status !== "EXECUTED") return;
  await db.responseAction.update({ where: { id: orig.id }, data: { status: "ROLLED_BACK" } });
  const open = await db.responseAction.count({ where: { caseId: orig.caseId, status: "EXECUTED", actionType: { in: [...CONTAINMENT_ACTIONS] } } });
  if (open === 0) await db.case.updateMany({ where: { id: orig.caseId, status: "CONTAINED" }, data: { status: "INVESTIGATING" } });
}

// A native connector's request the vendor has now confirmed (or that
// failed, or never confirmed in time): settle the action and the case.
export async function settleInProgressAction(actionId: string, outcome: { state: "confirmed" | "failed"; message: string }) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  if (action.status !== "IN_PROGRESS") return action;
  const kase = await db.case.findUniqueOrThrow({ where: { id: action.caseId } });
  const previous = (action.result ?? {}) as Record<string, unknown>;
  const confirmed = outcome.state === "confirmed";
  const status: ResponseActionStatus = confirmed ? "EXECUTED" : "FAILED";
  const summary = `${ACTION_LABEL[action.actionType]}${action.target ? ` ${action.target}` : ""}: ${outcome.message}`;
  const updated = await db.responseAction.update({
    where: { id: actionId },
    data: { status, result: JSON.parse(JSON.stringify({ ...previous, status: confirmed ? "succeeded" : "failed", summary, verifiedAt: new Date().toISOString() })) },
  });
  if (confirmed && (action.actionType === "ISOLATE_HOST" || action.actionType === "RELEASE_HOST") && action.target) {
    await setEndpointIsolation(kase, action.target, action.actionType === "ISOLATE_HOST", "connector");
  }
  await db.timelineEntry.create({
    data: { caseId: kase.id, occurredAt: new Date(), actor: "connector", action: `response.${action.actionType.toLowerCase()}`, detail: summary, evidence: { responseActionId: actionId, verified: confirmed } },
  });
  await logAction({ caseId: kase.id, action: confirmed ? "response.confirmed" : "response.failed", detail: { responseActionId: actionId, actionType: action.actionType, target: action.target, message: outcome.message } });
  if (confirmed) await completeRollbackOf(action.parameters);
  const { afterConnectorOutcome } = await import("@/lib/connectors/safety");
  await afterConnectorOutcome(updated, status);
  if (!confirmed) {
    await notify(await approversFor(kase.id), { kind: "approval", title: `Not confirmed: ${ACTION_LABEL[action.actionType]} ${action.target ?? ""}`, body: outcome.message, caseId: kase.id, actorName: "connector" });
  }
  await markCaseAfterResponse(kase.id);
  return updated;
}

// The analyst confirms they carried out a MANUAL_REQUIRED action themselves
// (in the EDR / IdP / firewall console). Their name and note become the
// record of it, and only now does it count as done.
export async function completeManualAction(actionId: string, actor: Actor & { id: string }, note: string) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  if (action.status !== "MANUAL_REQUIRED") throw new Error("This action isn't waiting to be done by hand");
  const confirmation = note.trim();
  if (confirmation.length < 3) throw new Error("Say what you did (for the record)");
  const kase = await db.case.findUniqueOrThrow({ where: { id: action.caseId } });
  const previous = (action.result ?? {}) as Record<string, unknown>;
  const summary = `${ACTION_LABEL[action.actionType]}${action.target ? ` ${action.target}` : ""} carried out by ${actor.name}: ${confirmation}`;
  const updated = await db.responseAction.update({
    where: { id: actionId },
    data: { status: "EXECUTED", result: JSON.parse(JSON.stringify({ ...previous, status: "succeeded", summary, manual: { by: actor.name, byId: actor.id, at: new Date().toISOString(), note: confirmation } })) },
  });
  if ((action.actionType === "ISOLATE_HOST" || action.actionType === "RELEASE_HOST") && action.target) {
    await setEndpointIsolation(kase, action.target, action.actionType === "ISOLATE_HOST", actor.name);
  }
  await db.timelineEntry.create({
    data: { caseId: kase.id, occurredAt: new Date(), actor: actor.name, action: `response.${action.actionType.toLowerCase()}`, detail: summary, evidence: { responseActionId: actionId, manual: true } },
  });
  await logAction({ actorId: actor.id, caseId: kase.id, action: "response.manual_completed", detail: { responseActionId: actionId, actionType: action.actionType, target: action.target, note: confirmation } });
  await completeRollbackOf(action.parameters);
  await markCaseAfterResponse(kase.id);
  return updated;
}

export async function decideResponseAction(actionId: string, decision: "approved" | "rejected", approver: Actor & { id: string }, note?: string) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  if (action.status !== "PENDING_APPROVAL" && action.status !== "SUGGESTED") throw new Error("Action is not awaiting a decision");
  const approvals = approvalsOf(action.approvals);
  if (decision === "approved" && approvals.some((a) => a.id === approver.id)) throw new Error("You've already approved this; it needs a second person");
  const nextApprovals = decision === "approved" ? [...approvals, { id: approver.id, name: approver.name, at: new Date().toISOString() }] : approvals;
  await db.responseAction.update({
    where: { id: actionId },
    data: {
      decidedById: approver.id,
      decidedAt: new Date(),
      approvals: JSON.parse(JSON.stringify(nextApprovals)),
      policyReason: note ? `${action.policyReason ?? ""}${action.policyReason ? " · " : ""}${decision} by ${approver.name}: ${note}` : action.policyReason,
    },
  });
  await logAction({ actorId: approver.id, caseId: action.caseId, action: `response.${decision}`, detail: { responseActionId: actionId, actionType: action.actionType, target: action.target, note, approvals: nextApprovals.length, required: action.requiredApprovals } });

  if (action.requestedById && action.requestedById !== approver.id) {
    await notify([action.requestedById], {
      kind: "approval",
      title: `${ACTION_LABEL[action.actionType]} ${action.target ?? ""} ${decision}`,
      body: note ?? null,
      caseId: action.caseId,
      actorName: approver.name,
    });
  }

  if (decision === "rejected") {
    const rejected = await db.responseAction.update({ where: { id: actionId }, data: { status: "REJECTED" } });
    await markCaseAfterResponse(action.caseId);
    return rejected;
  }
  // The two-person rule: wait for another approver.
  if (nextApprovals.length < action.requiredApprovals) {
    const waiting = await db.responseAction.update({ where: { id: actionId }, data: { status: "PENDING_APPROVAL" } });
    await notify(await approversFor(action.caseId), {
      kind: "approval",
      title: `Second approval needed: ${ACTION_LABEL[action.actionType]} ${action.target ?? ""}`,
      body: `${approver.name} approved; the client's rulebook needs ${action.requiredApprovals} people.`,
      caseId: action.caseId,
      actorName: approver.name,
    }, { exclude: approver.id });
    await markCaseAfterResponse(action.caseId);
    return waiting;
  }
  return performResponseAction(actionId, approver);
}

export async function rollbackResponseAction(actionId: string, actor: Actor & { id: string }) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  const inverse = ROLLBACK_OF[action.actionType];
  if (action.status !== "EXECUTED" || !inverse) throw new Error("This action can't be rolled back");
  const rollback = await recordResponseAction({
    caseId: action.caseId,
    actionType: inverse,
    target: action.target,
    source: "analyst",
    status: "PENDING_APPROVAL",
    rationale: `Rollback of ${ACTION_LABEL[action.actionType]}`,
    requestedById: actor.id,
    parameters: { rollbackOf: action.id },
  });
  // performResponseAction retires the original once the rollback has
  // actually happened (straight away via a connector, or when marked done).
  return performResponseAction(rollback.id, actor);
}

// An analyst asks for one action directly. People who may approve
// containment run it straight away; everyone else queues it for approval.
export async function requestAnalystAction(input: { caseId: string; actionType: PlaybookActionType; target: string; rationale?: string; actor: Actor & { id: string }; canApprove: boolean }) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: input.caseId }, select: { tenantId: true, severity: true } });
  // The client's rulebook binds analysts too: a forbidden action is recorded
  // as blocked, and the two-person rule sets how many approvals it needs.
  const gate = await humanRulebookGate({ tenantId: kase.tenantId, actionType: input.actionType, target: input.target, severity: kase.severity });
  if (!gate.allowed) {
    const blocked = await recordResponseAction({
      caseId: input.caseId,
      actionType: input.actionType,
      target: input.target,
      source: "analyst",
      status: "BLOCKED",
      rationale: input.rationale ?? null,
      policyReason: `${gate.reason} (rulebook v${gate.version})`,
      requestedById: input.actor.id,
      decision: { trace: [{ layer: "rulebook", rule: "hard", outcome: "BLOCKED", reason: gate.reason ?? "" }], approvals: 1, policyVersion: gate.version, policyHash: gate.hash },
    });
    await logAction({ actorId: input.actor.id, caseId: input.caseId, action: "response.blocked", detail: { responseActionId: blocked.id, actionType: input.actionType, target: input.target, reason: gate.reason, rulebookVersion: gate.version } });
    return blocked;
  }
  const twoPerson = gate.approvals > 1;
  const action = await recordResponseAction({
    caseId: input.caseId,
    actionType: input.actionType,
    target: input.target,
    source: "analyst",
    status: "PENDING_APPROVAL",
    rationale: input.rationale ?? null,
    policyReason: input.canApprove ? `Requested and approved by ${input.actor.name}${twoPerson ? `; ${gate.reason}` : ""}` : `Requested by ${input.actor.name}${twoPerson ? `; ${gate.reason}` : ""}`,
    requestedById: input.actor.id,
    decision: { trace: [], approvals: gate.approvals, policyVersion: gate.version, policyHash: gate.hash },
  });
  await logAction({ actorId: input.actor.id, caseId: input.caseId, action: "response.requested", detail: { responseActionId: action.id, actionType: input.actionType, target: input.target, requiredApprovals: gate.approvals } });
  if (input.canApprove) {
    const approvals = [{ id: input.actor.id, name: input.actor.name, at: new Date().toISOString() }];
    await db.responseAction.update({ where: { id: action.id }, data: { decidedById: input.actor.id, decidedAt: new Date(), approvals } });
    if (!twoPerson) return performResponseAction(action.id, input.actor);
    await markCaseAfterResponse(input.caseId);
    await notify(await approversFor(input.caseId), {
      kind: "approval",
      title: `Second approval needed: ${ACTION_LABEL[input.actionType]} ${input.target}`,
      body: `${input.actor.name} asked for and approved it; the client's rulebook needs ${gate.approvals} people.`,
      caseId: input.caseId,
      actorName: input.actor.name,
    }, { exclude: input.actor.id });
    return db.responseAction.findUniqueOrThrow({ where: { id: action.id } });
  }
  await markCaseAfterResponse(input.caseId);
  await notify(await approversFor(input.caseId), {
    kind: "approval",
    title: `Approval needed: ${ACTION_LABEL[input.actionType]} ${input.target}`,
    body: input.rationale ?? null,
    caseId: input.caseId,
    actorName: input.actor.name,
  }, { exclude: input.actor.id });
  return action;
}

export { markCaseAfterResponse };
