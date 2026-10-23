import type { Case, PlaybookAction, PlaybookExecution, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import {
  matchesTrigger,
  parseTrigger,
  renderTemplate,
  type CaseSnapshot,
} from "@/lib/playbooks/trigger";

// Ported from signal-fusion's services/playbookEngine.ts and generalized from
// Alert to the unified Case. Execution state lives in PlaybookExecution;
// approvals in PlaybookApproval; every step lands on the case timeline and
// in the audit log.

const CLOSED_STATUSES = new Set(["RESOLVED", "FALSE_POSITIVE"]);
const CONTAINMENT_ACTIONS = new Set(["ISOLATE_HOST", "BLOCK_IP", "KILL_PROCESS", "REVOKE_AGENT"]);

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
      const result = await runAction(action, kase, context);
      results.push(result);
      await db.timelineEntry.create({
        data: {
          caseId,
          occurredAt: new Date(),
          actor: `playbook:${playbook.name}`,
          action: `playbook.${action.actionType.toLowerCase()}`,
          detail: `${action.name}: ${result.summary}${result.simulated ? " (simulated — no integration configured)" : ""}`,
          evidence: result as never,
        },
      });
    } catch (err) {
      failure = err instanceof Error ? err.message : String(err);
      results.push({ action: action.name, actionType: action.actionType, status: "failed", summary: failure, simulated: false });
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

  const contained = !failure && results.some((r) => CONTAINMENT_ACTIONS.has(r.actionType) && r.status === "succeeded" && !r.skipped);
  if (contained && !CLOSED_STATUSES.has(kase.status)) {
    await db.case.update({ where: { id: caseId }, data: { status: "CONTAINED" } });
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

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export interface ActionResult {
  action: string;
  actionType: string;
  status: "succeeded" | "failed";
  summary: string;
  simulated: boolean;
  skipped?: boolean; // no-op (nothing to act on) — never counts as containment
  output?: Record<string, unknown>;
}

interface ActionContext {
  host?: string;
  user?: string;
  ips: string[];
  vars: Record<string, string | undefined>;
}

async function buildActionContext(kase: Case): Promise<ActionContext> {
  const metadata = (kase.metadata ?? {}) as Record<string, unknown>;
  const [hostEvent, userEvent, ipLinks] = await Promise.all([
    db.securityEvent.findFirst({ where: { caseId: kase.id, hostName: { not: null } }, select: { hostName: true } }),
    db.securityEvent.findFirst({ where: { caseId: kase.id, userName: { not: null } }, select: { userName: true } }),
    db.caseIndicator.findMany({ where: { caseId: kase.id, indicator: { type: "IP" } }, include: { indicator: true } }),
  ]);
  const host = (metadata.hostName as string | undefined) ?? hostEvent?.hostName ?? undefined;
  const user = (metadata.userName as string | undefined) ?? userEvent?.userName ?? undefined;
  const ips = ipLinks.map((l) => l.indicator.value);
  return {
    host,
    user,
    ips,
    vars: {
      "case.id": kase.id,
      "case.title": kase.title,
      "case.severity": kase.severity,
      "case.source": kase.sourceType.replaceAll("_", " "),
      host: host ?? "unknown host",
      user: user ?? "unknown user",
      ips: ips.length ? ips.join(", ") : "no IPs",
    },
  };
}

function param(action: PlaybookAction, key: string): string | undefined {
  const params = (action.parameters ?? {}) as Prisma.JsonObject;
  const value = params[key];
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : undefined;
}

async function runAction(action: PlaybookAction, kase: Case, ctx: ActionContext): Promise<ActionResult> {
  const base = { action: action.name, actionType: action.actionType };

  switch (action.actionType) {
    case "BLOCK_IP": {
      const explicit = param(action, "ip");
      const ips = explicit ? [explicit] : ctx.ips;
      if (ips.length === 0) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No public IPs linked to this case — nothing to block" };
      }
      // A real effect inside HELIOS: the shared indicator store doubles as the
      // blocklist exported on the Threat Intelligence page.
      for (const ip of ips) {
        await db.threatIndicator.upsert({
          where: { type_value: { type: "IP", value: ip } },
          update: { blockedAt: new Date() },
          create: { type: "IP", value: ip, providerData: {}, sources: [], expiresAt: new Date(), blockedAt: new Date() },
        });
      }
      return { ...base, status: "succeeded", simulated: false, summary: `Added ${ips.join(", ")} to the HELIOS blocklist`, output: { blocked: ips } };
    }

    case "REVOKE_AGENT":
    case "RESTORE_AGENT": {
      if (kase.sourceType !== "AGENT_GOVERNANCE" || !kase.sourceRef) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "Case is not tied to an AI agent — skipped" };
      }
      const revoke = action.actionType === "REVOKE_AGENT";
      const agent = await db.agent.update({
        where: { id: kase.sourceRef },
        data: revoke
          ? { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" }
          : { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
      });
      return {
        ...base,
        status: "succeeded",
        simulated: false,
        summary: `${revoke ? "Revoked" : "Restored"} agent ${agent.name}`,
        output: { agentId: agent.id, status: agent.status },
      };
    }

    case "COLLECT_LOGS": {
      // Pull related telemetry (same host or user, ±window) into the case.
      const windowMinutes = Number(param(action, "windowMinutes") ?? 60);
      const or: Prisma.SecurityEventWhereInput[] = [];
      if (ctx.host) or.push({ hostName: ctx.host });
      if (ctx.user) or.push({ userName: ctx.user });
      if (or.length === 0) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No host or user on this case to collect telemetry for" };
      }
      const from = new Date(kase.createdAt.getTime() - windowMinutes * 60_000);
      const to = new Date(kase.createdAt.getTime() + windowMinutes * 60_000);
      const { count } = await db.securityEvent.updateMany({
        where: { caseId: null, OR: or, timestamp: { gte: from, lte: to } },
        data: { caseId: kase.id },
      });
      return { ...base, status: "succeeded", simulated: false, summary: `Attached ${count} related events to the case`, output: { attached: count } };
    }

    case "NOTIFY_SLACK": {
      const message = renderTemplate(param(action, "message") ?? "HELIOS case update: {{case.title}}", ctx.vars);
      const channel = param(action, "channel");
      const webhook = process.env.SLACK_WEBHOOK_URL;
      if (!webhook) {
        return { ...base, status: "succeeded", simulated: true, summary: `Would post to ${channel ?? "Slack"}: "${message}"`, output: { channel, message } };
      }
      const res = await fetch(webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: message, channel }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`Slack webhook returned HTTP ${res.status}`);
      return { ...base, status: "succeeded", simulated: false, summary: `Posted to ${channel ?? "Slack"}: "${message}"`, output: { channel, message } };
    }

    case "CREATE_TICKET": {
      const title = renderTemplate(param(action, "title") ?? "{{case.title}}", ctx.vars);
      const project = param(action, "project") ?? "SEC";
      const ticketId = `${project}-${kase.id.slice(-6).toUpperCase()}`;
      return { ...base, status: "succeeded", simulated: true, summary: `Ticket ${ticketId}: "${title}"`, output: { ticketId, title, system: param(action, "system") ?? "jira" } };
    }

    case "ISOLATE_HOST": {
      const host = param(action, "host") ?? ctx.host;
      if (!host) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No host identified on this case — nothing to isolate" };
      }
      return { ...base, status: "succeeded", simulated: true, summary: `Isolated ${host} via ${param(action, "method") ?? "EDR containment"}`, output: { host } };
    }

    case "KILL_PROCESS": {
      const process = param(action, "process") ?? "the flagged process";
      return { ...base, status: "succeeded", simulated: true, summary: `Terminated ${process} on ${ctx.host ?? "the affected host"}`, output: { process, host: ctx.host } };
    }
  }
}
