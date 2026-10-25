import type { ResponseAction, ResponseActionStatus } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { ACTION_LABEL } from "@/lib/response/labels";
import { activeRulebook } from "@/lib/rulebook/service";
import { verifyNative } from "@/lib/connectors/run";
import type { VendorRef } from "@/lib/connectors/types";

// What keeps real containment safe once connectors act:
//   the circuit breaker — repeated connector failures for a client pause
//     its automatic containment (actions wait for a human) and page the SOC
//     until someone resumes it;
//   time boxes — an IP block or account disable rolls itself back when its
//     time is up, unless someone extends it (the client's rulebook sets the
//     hours);
//   verification — requests waiting on the vendor are checked until they're
//     confirmed, fail, or run out of time.

export const BREAKER = { failures: 3, windowMinutes: 30 };
export const VERIFY_TIMEOUT_MINUTES = 30;

export async function circuitBreakerFor(tenantId: string | null | undefined) {
  if (!tenantId) return null;
  const t = await db.tenant.findUnique({ where: { id: tenantId }, select: { automationPausedAt: true, automationPauseReason: true } });
  return t?.automationPausedAt ? { since: t.automationPausedAt, reason: t.automationPauseReason ?? "paused" } : null;
}

export async function pauseAutomation(tenantId: string, reason: string, actorId?: string) {
  const t = await db.tenant.update({ where: { id: tenantId }, data: { automationPausedAt: new Date(), automationPauseReason: reason }, select: { name: true } });
  await logAction({ actorId, action: "automation.paused", detail: { tenantId, reason } });
  await notify(await staffFor(["SOC_MANAGER", "INCIDENT_RESPONDER"], null), {
    kind: "approval",
    title: `Automatic containment paused for ${t.name}`,
    body: `${reason}. AI containment now waits for approval until someone resumes it on the client's rulebook page.`,
    href: `/rulebook?tenant=${tenantId}`,
  });
}

export async function resumeAutomation(tenantId: string, actor: { id: string; name: string }) {
  await db.tenant.update({ where: { id: tenantId }, data: { automationPausedAt: null, automationPauseReason: null } });
  await logAction({ actorId: actor.id, action: "automation.resumed", detail: { tenantId } });
}

function dispatchedFailure(a: Pick<ResponseAction, "result">) {
  const output = (a.result as { output?: { connector?: { dispatched?: boolean }; connectors?: Array<{ dispatched?: boolean }> } } | null)?.output;
  return !!output?.connector?.dispatched || !!output?.connectors?.some((c) => c.dispatched);
}

// Called after an action settles (executed, or failed at a connector).
export async function afterConnectorOutcome(action: ResponseAction, status: ResponseActionStatus) {
  if (!action.tenantId) return;
  if (status === "FAILED" && dispatchedFailure(action)) {
    const since = new Date(Date.now() - BREAKER.windowMinutes * 60_000);
    const recent = await db.responseAction.findMany({ where: { tenantId: action.tenantId, status: "FAILED", createdAt: { gte: since } }, select: { result: true } });
    const failures = recent.filter(dispatchedFailure).length;
    if (failures >= BREAKER.failures && !(await circuitBreakerFor(action.tenantId))) {
      await pauseAutomation(action.tenantId, `${failures} connector failures in ${BREAKER.windowMinutes} minutes`);
    }
  }
  if (status === "EXECUTED" && !action.expiresAt && !isRollback(action.parameters)) {
    const rb = await activeRulebook(action.tenantId);
    const hours = action.actionType === "BLOCK_IP" ? rb?.body.timeBoxes.blockIpHours : action.actionType === "DISABLE_USER" ? rb?.body.timeBoxes.disableUserHours : 0;
    if (hours) await db.responseAction.update({ where: { id: action.id }, data: { expiresAt: new Date(Date.now() + hours * 3_600_000) } });
  }
}

const isRollback = (parameters: unknown) => !!parameters && typeof parameters === "object" && "rollbackOf" in parameters;

// Someone keeps a time-boxed action longer (or for good, with hours = 0).
export async function extendAction(actionId: string, hours: number, actor: { id: string; name: string }) {
  const action = await db.responseAction.findUniqueOrThrow({ where: { id: actionId } });
  if (action.status !== "EXECUTED" || !action.expiresAt) throw new Error("This action has no time box");
  const expiresAt = hours > 0 ? new Date(Math.max(Date.now(), action.expiresAt.getTime()) + hours * 3_600_000) : null;
  await db.responseAction.update({ where: { id: actionId }, data: { expiresAt } });
  await logAction({ actorId: actor.id, caseId: action.caseId, action: "response.extended", detail: { responseActionId: actionId, hours, expiresAt: expiresAt?.toISOString() ?? null } });
  return expiresAt;
}

// ---------------------------------------------------------------- jobs

interface PendingRef {
  integrationId: string;
  native: string;
  ref: VendorRef;
  target: string;
}

export async function verifyInProgress(now = new Date()) {
  const actions = await db.responseAction.findMany({ where: { status: "IN_PROGRESS" }, take: 200 });
  const { settleInProgressAction } = await import("@/lib/response/service");
  let settled = 0;
  for (const a of actions) {
    const pending = ((a.result as { output?: { pending?: PendingRef[] } } | null)?.output?.pending ?? []).filter((p) => p.integrationId && p.ref);
    const checks = await Promise.all(pending.map((p) => verifyNative(p.integrationId, a.actionType, p.ref)));
    const failed = checks.find((c) => c.state === "failed");
    const started = a.decidedAt ?? a.createdAt;
    if (!pending.length || failed) {
      await settleInProgressAction(a.id, { state: "failed", message: failed?.message ?? "Nothing to verify" });
      settled++;
    } else if (checks.every((c) => c.state === "confirmed")) {
      await settleInProgressAction(a.id, { state: "confirmed", message: checks.map((c) => c.message).join("; ") });
      settled++;
    } else if (now.getTime() - started.getTime() > VERIFY_TIMEOUT_MINUTES * 60_000) {
      await settleInProgressAction(a.id, { state: "failed", message: `Not confirmed within ${VERIFY_TIMEOUT_MINUTES} minutes (${checks.map((c) => c.message).join("; ")}); check the tool's console` });
      settled++;
    }
  }
  return settled;
}

// Time boxes that ran out: roll the action back through the normal path.
export async function rollBackExpired(now = new Date()) {
  const expired = await db.responseAction.findMany({ where: { status: "EXECUTED", expiresAt: { lte: now } }, take: 100 });
  const { recordResponseAction, performResponseAction } = await import("@/lib/response/service");
  const { ROLLBACK_OF } = await import("@/lib/response/executor");
  for (const a of expired) {
    const inverse = ROLLBACK_OF[a.actionType];
    await db.responseAction.update({ where: { id: a.id }, data: { expiresAt: null } });
    if (!inverse) continue;
    const rollback = await recordResponseAction({
      caseId: a.caseId,
      actionType: inverse,
      target: a.target,
      source: "analyst",
      status: "PENDING_APPROVAL",
      rationale: `Time box ended: ${ACTION_LABEL[a.actionType]} was set to expire`,
      parameters: { rollbackOf: a.id },
    });
    await logAction({ caseId: a.caseId, action: "response.time_box_ended", detail: { responseActionId: a.id, rollbackId: rollback.id } });
    await performResponseAction(rollback.id, { name: "time box" });
  }
  return expired.length;
}

// A connector's credential that's about to expire: tell the SOC and the
// client's admins, once per expiry date.
export async function credentialReminders(now = new Date()) {
  const integrations = await db.integration.findMany({ where: { enabled: true }, select: { id: true, name: true, tenantId: true, config: true } });
  let sent = 0;
  for (const i of integrations) {
    const config = (i.config ?? {}) as { credentialExpiresAt?: string; credentialReminderFor?: string };
    if (!config.credentialExpiresAt || config.credentialReminderFor === config.credentialExpiresAt) continue;
    const expires = new Date(config.credentialExpiresAt);
    const days = (expires.getTime() - now.getTime()) / 86_400_000;
    if (Number.isNaN(days) || days > 14) continue;
    const admins = i.tenantId ? await db.user.findMany({ where: { tenantId: i.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } }) : [];
    await notify([...(await staffFor(["SOC_MANAGER"], null)), ...admins.map((a) => a.id)], {
      kind: "approval",
      title: days < 0 ? `${i.name}: connector credential expired` : `${i.name}: connector credential expires in ${Math.ceil(days)} day${Math.ceil(days) === 1 ? "" : "s"}`,
      body: "Issue a new secret in the vendor's console and update the connector, or containment through it will stop.",
      href: "/integrations",
    });
    await db.integration.update({ where: { id: i.id }, data: { config: { ...config, credentialReminderFor: config.credentialExpiresAt } } });
    sent++;
  }
  return sent;
}
