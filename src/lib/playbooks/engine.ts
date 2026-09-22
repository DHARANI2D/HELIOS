import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import type { Case, Playbook, PlaybookAction, PlaybookActionType } from "@prisma/client";

// Ported from signal-fusion's services/playbookEngine.ts — generalized to
// trigger from any Case (not just SIEM alerts), matching the unified
// model. Trigger shape: { severity?, sourceType?, minRiskScore?,
// mitreTechnique? } stored as JSON on Playbook.triggerCondition.

interface TriggerCondition {
  severity?: string;
  sourceType?: string;
  minRiskScore?: number;
  mitreTechnique?: string;
}

function caseMitreTechniques(kase: Case): string[] {
  const metadata = kase.metadata as { mitreTechniques?: string[] } | null;
  return metadata?.mitreTechniques ?? [];
}

export function matchesTrigger(playbook: Playbook, kase: Case): boolean {
  const trigger = playbook.triggerCondition as TriggerCondition;

  if (trigger.severity && kase.severity !== trigger.severity) return false;
  if (trigger.sourceType && kase.sourceType !== trigger.sourceType) return false;
  if (trigger.minRiskScore && (kase.riskScore ?? 0) < trigger.minRiskScore) return false;
  if (trigger.mitreTechnique && !caseMitreTechniques(kase).includes(trigger.mitreTechnique)) {
    return false;
  }

  return true;
}

export async function evaluateTriggers(kase: Case): Promise<Playbook[]> {
  const playbooks = await db.playbook.findMany({
    where: { enabled: true },
    orderBy: { priority: "desc" },
  });
  return playbooks.filter((p) => matchesTrigger(p, kase));
}

async function executeAction(action: PlaybookAction, kase: Case): Promise<Record<string, unknown>> {
  const params = (action.parameters ?? {}) as Record<string, unknown>;

  switch (action.actionType as PlaybookActionType) {
    case "ISOLATE_HOST":
      return { isolated: true, host: params.hostname ?? kase.sourceRef ?? "unknown" };
    case "BLOCK_IP":
      return { blocked: true, ip: params.ip ?? "unknown" };
    case "NOTIFY_SLACK":
      return { notified: true, channel: params.channel ?? "#security" };
    case "CREATE_TICKET":
      return { ticketId: `TICKET-${Date.now()}`, title: params.title ?? kase.title };
    case "KILL_PROCESS":
      return { killed: true, process: params.process ?? "unknown" };
    case "COLLECT_LOGS":
      return { collected: true, scope: params.scope ?? "host" };
    case "REVOKE_AGENT": {
      if (kase.sourceType === "AGENT_GOVERNANCE" && kase.sourceRef) {
        await db.agent.update({
          where: { id: kase.sourceRef },
          data: { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" },
        });
        return { revoked: true, agentId: kase.sourceRef };
      }
      return { revoked: false, reason: "case has no linked agent" };
    }
    case "RESTORE_AGENT": {
      if (kase.sourceType === "AGENT_GOVERNANCE" && kase.sourceRef) {
        await db.agent.update({
          where: { id: kase.sourceRef },
          data: { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
        });
        return { restored: true, agentId: kase.sourceRef };
      }
      return { restored: false, reason: "case has no linked agent" };
    }
  }
}

export async function executePlaybook(playbookId: string, caseId: string, existingExecutionId?: string) {
  const playbook = await db.playbook.findUniqueOrThrow({
    where: { id: playbookId },
    include: { actions: { orderBy: { order: "asc" } } },
  });
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId } });

  // Reuse the PENDING_APPROVAL row when approving one, instead of always
  // creating a fresh execution — otherwise the original row never leaves
  // PENDING_APPROVAL and stays stuck in the pending-approvals list forever,
  // even after being approved and actually run under a different row.
  const execution = existingExecutionId
    ? await db.playbookExecution.update({
        where: { id: existingExecutionId },
        data: { status: "RUNNING" },
      })
    : await db.playbookExecution.create({
        data: { playbookId, caseId, status: "RUNNING" },
      });

  const results: Array<{ action: string; status: string; output?: unknown; error?: string }> = [];

  for (const action of playbook.actions) {
    try {
      const output = await executeAction(action, kase);
      results.push({ action: action.name, status: "success", output });
    } catch (err) {
      results.push({ action: action.name, status: "failed", error: err instanceof Error ? err.message : String(err) });
      await db.playbookExecution.update({
        where: { id: execution.id },
        data: { status: "FAILED", finishedAt: new Date(), results: results as never },
      });
      await logAction({ caseId, action: "playbook.execution_failed", detail: { playbookId, results } });
      return execution.id;
    }
  }

  await db.playbookExecution.update({
    where: { id: execution.id },
    data: { status: "SUCCEEDED", finishedAt: new Date(), results: results as never },
  });

  await db.timelineEntry.create({
    data: {
      caseId,
      occurredAt: new Date(),
      action: "playbook_executed",
      detail: `${playbook.name} (${results.length} action(s))`,
      evidence: results as never,
    },
  });

  await logAction({ caseId, action: "playbook.executed", detail: { playbookId, results } });

  return execution.id;
}

export async function requestApproval(playbookId: string, caseId: string) {
  const execution = await db.playbookExecution.create({
    data: { playbookId, caseId, status: "PENDING_APPROVAL" },
  });
  await logAction({ caseId, action: "playbook.approval_requested", detail: { playbookId } });
  return execution.id;
}

export async function decideApproval(
  executionId: string,
  approverId: string,
  decision: "approved" | "rejected",
  notes?: string,
) {
  const execution = await db.playbookExecution.findUniqueOrThrow({ where: { id: executionId } });

  await db.playbookApproval.create({
    data: { executionId, approverId, decision, notes },
  });

  if (decision === "rejected") {
    await db.playbookExecution.update({ where: { id: executionId }, data: { status: "REJECTED" } });
    await logAction({ caseId: execution.caseId, action: "playbook.approval_rejected", detail: { executionId, approverId } });
    return;
  }

  await executePlaybook(execution.playbookId, execution.caseId, execution.id);
}

// Wired into the detection engine and other case-producing modules: after
// a case is created, auto-execute matching auto-execute playbooks, or
// queue an approval request for the rest.
export async function runPlaybooksForCase(kase: Case) {
  const matched = await evaluateTriggers(kase);
  for (const playbook of matched) {
    if (playbook.autoExecute && !playbook.requireApproval) {
      await executePlaybook(playbook.id, kase.id);
    } else if (playbook.requireApproval) {
      await requestApproval(playbook.id, kase.id);
    }
  }
}
