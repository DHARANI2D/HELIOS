import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { dispatchChatMessage } from "@/lib/integrations/chat";
import { ACTION_LABEL } from "@/lib/response/labels";
import { activeRulebook } from "@/lib/rulebook/service";
import { APPROVER_CHANNELS, type Approver } from "@/lib/rulebook/schema";

// Pending approvals walk the client's approver chain: the first approver
// has their timeout, then the next one is asked, and when the chain runs
// out the rulebook says whether the action keeps holding or becomes a
// suggestion. Nothing ever runs because nobody answered. The sweep runs on
// the background schedule (lib/jobs) and is safe to repeat.

// Which step of the chain should be asked after `ageMinutes`, and whether
// the whole chain has timed out. Pure.
export function chainPosition(chain: Pick<Approver, "timeoutMinutes">[], ageMinutes: number): { step: number; expired: boolean } {
  let elapsed = 0;
  for (const [i, a] of chain.entries()) {
    elapsed += a.timeoutMinutes;
    if (ageMinutes < elapsed) return { step: i, expired: false };
  }
  return { step: chain.length - 1, expired: true };
}

interface EscalationState {
  step: number;
  at: string;
  timedOut?: boolean;
}

function stateOf(value: unknown): EscalationState | null {
  return value && typeof value === "object" && typeof (value as EscalationState).step === "number" ? (value as EscalationState) : null;
}

async function ask(approver: Approver, tenantId: string, caseId: string, title: string) {
  if (approver.channel === "app") {
    const users = await db.user.findMany({ where: { email: { equals: approver.contact, mode: "insensitive" }, active: true }, select: { id: true } });
    if (users.length) {
      await notify(users.map((u) => u.id), { kind: "approval", title, body: "Your approval is needed (client approver chain).", caseId });
      return `notified ${approver.name} in HELIOS`;
    }
  }
  if (approver.channel === "slack" || approver.channel === "teams") {
    const sent = await dispatchChatMessage(tenantId, `${title} — ${approver.name}, please review in HELIOS.`);
    if (sent.sent) return `posted to ${APPROVER_CHANNELS[approver.channel]} for ${approver.name}`;
  }
  // Email and phone (or a channel that couldn't be reached) go through the
  // SOC: HELIOS doesn't send email or place calls itself.
  await notify(await staffFor(["SOC_MANAGER", "INCIDENT_RESPONDER"], null), {
    kind: "approval",
    title: `Contact ${approver.name} for approval`,
    body: `${title}. Reach them by ${APPROVER_CHANNELS[approver.channel].toLowerCase()}: ${approver.contact}.`,
    caseId,
  });
  return `asked the SOC to contact ${approver.name} by ${APPROVER_CHANNELS[approver.channel].toLowerCase()}`;
}

export async function escalatePendingApprovals(now = new Date()) {
  const pending = await db.responseAction.findMany({
    where: { status: "PENDING_APPROVAL", tenantId: { not: null }, createdAt: { gte: new Date(now.getTime() - 7 * 86_400_000) } },
    include: { case: { select: { title: true } } },
    take: 500,
  });
  let changed = 0;
  for (const action of pending) {
    const rb = await activeRulebook(action.tenantId);
    const chain = rb?.body.approvers.chain ?? [];
    if (!rb || chain.length === 0) continue;
    const state = stateOf(action.escalation);
    if (state?.timedOut) continue;
    const age = (now.getTime() - action.createdAt.getTime()) / 60_000;
    const { step, expired } = chainPosition(chain, age);
    const title = `${ACTION_LABEL[action.actionType]}${action.target ? ` ${action.target}` : ""} on "${action.case.title}"`;

    if (expired) {
      const total = chain.reduce((n, a) => n + a.timeoutMinutes, 0);
      if (rb.body.approvers.onTimeout === "suggest") {
        await db.responseAction.update({
          where: { id: action.id },
          data: { status: "SUGGESTED", escalation: { step, at: now.toISOString(), timedOut: true }, policyReason: `${action.policyReason ?? ""} · no approver answered within ${total} min; downgraded to a suggestion (rulebook v${rb.version})` },
        });
      } else {
        await db.responseAction.update({ where: { id: action.id }, data: { escalation: { step, at: now.toISOString(), timedOut: true } } });
        await notify(await staffFor(["SOC_MANAGER"], null), { kind: "approval", title: `No client approver answered: ${title}`, body: `Still holding after ${total} min; nothing runs until someone approves.`, caseId: action.caseId });
      }
      await db.timelineEntry.create({ data: { caseId: action.caseId, occurredAt: now, actor: "approver chain", action: "response.approval_timed_out", detail: `${title}: no answer within ${total} min — ${rb.body.approvers.onTimeout === "suggest" ? "downgraded to a suggestion" : "still holding"}` } });
      await logAction({ caseId: action.caseId, action: "response.approval_timed_out", detail: { responseActionId: action.id, rulebookVersion: rb.version, onTimeout: rb.body.approvers.onTimeout } });
      changed++;
      continue;
    }
    if (state && state.step >= step) continue;
    const how = await ask(chain[step], action.tenantId!, action.caseId, `Approval needed: ${title}`);
    await db.responseAction.update({ where: { id: action.id }, data: { escalation: { step, at: now.toISOString() } } });
    await db.timelineEntry.create({ data: { caseId: action.caseId, occurredAt: now, actor: "approver chain", action: "response.approval_escalated", detail: `Step ${step + 1} of ${chain.length}: ${how}` } });
    changed++;
  }
  return changed;
}
