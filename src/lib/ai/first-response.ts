import { after } from "next/server";
import type { CaseSeverity, PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { aiSettings } from "@/lib/settings";
import { notify, staffFor } from "@/lib/notifications";
import { severityRank } from "@/lib/severity";
import { AGENT_TYPES, type AgentKey } from "@/lib/ai/catalog";
import { aiCostOf } from "@/lib/pricing/service";
import { gatherEvidence } from "@/lib/ai/evidence";
import { loadProfile, resolveAgent } from "@/lib/ai/resolve";
import { withRedaction } from "@/lib/ai/gateway";
import { analyzeCase, runReportAgent, type CaseAnalysis } from "@/lib/ai/agents";
import { SEVERITY_FROM_AI, type TriageOutput } from "@/lib/ai/triage";
import { decideResponse } from "@/lib/response/policy";
import { rulebookVerdict } from "@/lib/rulebook/service";
import { ladderFor, observing } from "@/lib/shadow/service";
import { circuitBreakerFor } from "@/lib/connectors/safety";
import { ACTION_LABEL } from "@/lib/response/executor";
import { approversFor, markCaseAfterResponse, performResponseAction, recordResponseAction } from "@/lib/response/service";

// AI first response: every new case (above the configured severity) gets a
// triage agent's initial analysis within seconds, containment through the
// response policy, and a hand-off to the right analyst tier. Analysts can
// also dispatch any case-level agent by hand from the case page.

const CLOSED = ["RESOLVED", "FALSE_POSITIVE"];
const MAX_CONCURRENT = Number(process.env.AI_MAX_CONCURRENT_RUNS ?? 2);

// A small in-process queue so a burst of new cases (a log upload, a noisy
// tool) doesn't fan out into dozens of simultaneous model calls.
let running = 0;
const waiting: Array<() => void> = [];
async function withSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (running >= MAX_CONCURRENT) await new Promise<void>((resolve) => waiting.push(resolve));
  running++;
  try {
    return await fn();
  } finally {
    running--;
    waiting.shift()?.();
  }
}

export function firstResponseDisabledByEnv() {
  return process.env.HELIOS_AI_FIRST_RESPONSE === "off";
}

export function scheduleFirstResponse(caseId: string) {
  if (firstResponseDisabledByEnv()) return;
  const job = () => maybeRunFirstResponse(caseId).catch((err) => console.error("AI first response failed", caseId, err));
  try {
    after(job);
  } catch {
    void job();
  }
}

export async function maybeRunFirstResponse(caseId: string) {
  const settings = await aiSettings();
  if (!settings.firstResponse) return null;
  // Claim the case atomically so a correlation burst runs it once.
  const kase = await db.case.findUnique({ where: { id: caseId }, select: { severity: true, status: true, aiStatus: true } });
  if (!kase || kase.aiStatus || CLOSED.includes(kase.status)) return null;
  if (severityRank(kase.severity) < severityRank(settings.minSeverity)) {
    await db.case.updateMany({ where: { id: caseId, aiStatus: null }, data: { aiStatus: "skipped" } });
    return null;
  }
  const claimed = await db.case.updateMany({ where: { id: caseId, aiStatus: null }, data: { aiStatus: "queued" } });
  if (claimed.count === 0) return null;
  const agent = (await db.case.findUnique({ where: { id: caseId }, select: { sourceType: true } }))?.sourceType === "EMAIL_ANALYSIS" ? "phishing" : "triage";
  return withSlot(() => runAgentOnCase(caseId, agent, { trigger: "auto" }));
}

export interface DispatchOptions {
  trigger: "auto" | "manual";
  requestedBy?: { id: string; name: string };
}

export async function runAgentOnCase(caseId: string, key: AgentKey, opts: DispatchOptions) {
  if (key === "containment" || key === "investigation" || key === "advisor" || !AGENT_TYPES[key]?.dispatchable) throw new Error(`${key} can't be dispatched onto a case`);
  const scope = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { tenantId: true, severity: true } });
  const resolved = await resolveAgent(key, { tenantId: scope.tenantId, userId: opts.requestedBy?.id, severity: scope.severity });
  const { profile, resolution } = resolved;
  let provider = resolved.provider;
  if (!profile.enabled || profile.autonomy === "OFF") {
    await db.case.updateMany({ where: { id: caseId, aiStatus: "queued" }, data: { aiStatus: "skipped" } });
    throw new Error(`${profile.name} is turned off`);
  }
  await db.case.update({ where: { id: caseId }, data: { aiStatus: "running" } });

  const runScope = { tenantId: scope.tenantId, resolution: resolution ? JSON.parse(JSON.stringify(resolution)) : undefined };
  try {
    const evidence = await gatherEvidence(caseId);
    // The client's rulebook may require personal data masked for cloud models.
    if (provider && resolved.redact) provider = withRedaction(provider, { hosts: evidence.entities.hosts, users: evidence.entities.users, emails: evidence.entities.emails, ips: evidence.entities.ips }).provider;

    if (key === "report") {
      const [latest, actions] = await Promise.all([
        db.aiRun.findFirst({ where: { caseId, agentKey: { in: ["triage", "phishing", "threat_intel"] }, status: { not: "failed" } }, orderBy: { createdAt: "desc" } }),
        db.responseAction.findMany({ where: { caseId, status: { not: "SHADOW" } }, orderBy: { createdAt: "asc" } }),
      ]);
      const outcome = await runReportAgent(
        evidence,
        {
          triage: (latest?.output as TriageOutput | null) ?? null,
          actions: actions.map((a) => ({ label: ACTION_LABEL[a.actionType], target: a.target, status: a.status, manual: !!(a.result as { manual?: unknown } | null)?.manual })),
        },
        profile,
        provider,
      );
      const run = await db.aiRun.create({
        data: {
          caseId, ...runScope, agentKey: key, trigger: opts.trigger, engine: outcome.engine, model: outcome.model, isLocal: outcome.isLocal, status: outcome.status,
          output: { markdown: outcome.output }, error: outcome.error, durationMs: outcome.durationMs,
          inputTokens: outcome.usage.inputTokens, outputTokens: outcome.usage.outputTokens, requestedById: opts.requestedBy?.id,
        },
      });
      await db.caseComment.create({
        data: { caseId, authorName: `${profile.name} · ${outcome.engine}`, kind: "ai_report", body: outcome.output, internal: true },
      });
      await finishRun(caseId, key, run.id, outcome.engine, outcome.model, outcome.status, opts, {});
      return run;
    }

    const { outcome, output, report, manipulated } = await analyzeCase(key, evidence, profile, provider);
    const run = await db.aiRun.create({
      data: {
        caseId, ...runScope, agentKey: key, trigger: opts.trigger, engine: outcome.engine, model: outcome.model, isLocal: outcome.isLocal, status: outcome.status,
        confidence: output.confidence, output: JSON.parse(JSON.stringify(output)), grounding: JSON.parse(JSON.stringify(report)),
        error: outcome.error, durationMs: outcome.durationMs, inputTokens: outcome.usage.inputTokens, outputTokens: outcome.usage.outputTokens,
        requestedById: opts.requestedBy?.id,
      },
    });
    // A client-picked model that hasn't passed its evaluation only suggests;
    // the built-in engine (after a fallback) isn't capped by it.
    const modelCap = resolved.autonomyCap && outcome.engine !== "built-in" ? { autonomy: resolved.autonomyCap, reason: resolution?.capReason ?? "Model not evaluated" } : null;
    const { statuses, silent } = await applyTriage(caseId, run.id, output, report, profile.name, outcome.engine, opts, modelCap, manipulated);
    // Shadow-mode runs stay out of sight on the case until it closes.
    if (silent) await db.aiRun.update({ where: { id: run.id }, data: { resolution: { ...((runScope.resolution as object | undefined) ?? {}), shadow: true } } });
    await finishRun(caseId, key, run.id, outcome.engine, outcome.model, outcome.status, opts, { verdict: output.verdict, confidence: output.confidence, actions: statuses, grounding: report.notes });
    return run;
  } catch (err) {
    await db.case.update({ where: { id: caseId }, data: { aiStatus: "failed" } });
    await db.aiRun.create({ data: { caseId, ...runScope, agentKey: key, trigger: opts.trigger, engine: provider?.name ?? "built-in", model: provider?.model, status: "failed", error: err instanceof Error ? err.message : String(err), requestedById: opts.requestedBy?.id } });
    throw err;
  }
}

async function finishRun(
  caseId: string,
  key: AgentKey,
  runId: string,
  engine: string,
  model: string | null,
  status: string,
  opts: DispatchOptions,
  detail: Record<string, unknown>,
) {
  await db.case.update({ where: { id: caseId }, data: { aiStatus: "completed" } });
  await logAction({
    actorId: opts.requestedBy?.id,
    caseId,
    action: "ai.run",
    detail: { runId, agent: key, trigger: opts.trigger, engine, model, status, ...detail },
  });
}

async function applyTriage(
  caseId: string,
  runId: string,
  output: TriageOutput,
  report: CaseAnalysis["report"],
  agentName: string,
  engine: string,
  opts: DispatchOptions,
  modelCap: { autonomy: "SUGGEST"; reason: string } | null = null,
  manipulated = false,
) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, include: { tenant: { select: { aiAutonomyCap: true, plan: { select: { defaultAutonomyCap: true } } } } } });
  const [settings, controller, ladder, paused] = await Promise.all([aiSettings(), loadProfile("containment"), ladderFor(kase.tenantId), circuitBreakerFor(kase.tenantId)]);
  const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
  // Shadow mode: with every action at level 0 the AI only observes — its
  // analysis is recorded but stays out of sight until the case closes.
  const silent = observing(ladder);

  const statuses: Array<{ action: PlaybookActionType; target: string; status: string; reason: string }> = [];
  const pendingLabels: string[] = [];

  for (const [i, proposed] of output.recommended_actions.entries()) {
    const ground = report.actions[i];
    const target = ground?.matched ?? proposed.target;
    // Don't propose the same thing twice on one case.
    const duplicate = await db.responseAction.findFirst({ where: { caseId, actionType: proposed.action, target, status: { in: ["PENDING_APPROVAL", "EXECUTED", "SUGGESTED", "SHADOW"] } } });
    if (duplicate) continue;

    const endpoint = proposed.action === "ISOLATE_HOST" ? await db.endpoint.findFirst({ where: { tenantId: kase.tenantId, hostname: { equals: target, mode: "insensitive" } }, select: { criticality: true } }) : null;
    // A host the client's inventory doesn't know is never isolated automatically.
    const targetUnknown = proposed.action === "ISOLATE_HOST" && !!kase.tenantId && !endpoint;
    const autoActionsLastHour = await db.responseAction.count({ where: { tenantId: kase.tenantId, source: "ai", status: "EXECUTED", createdAt: { gte: hourAgo } } });
    const rulebook = await rulebookVerdict({ tenantId: kase.tenantId, actionType: proposed.action, target, severity: kase.severity });
    const level = ladder?.get(proposed.action) ?? null;
    const decision = decideResponse({
      actionType: proposed.action,
      grounded: !!ground?.grounded,
      confidence: output.confidence,
      killSwitch: settings.killSwitch,
      paused,
      autonomy: controller.enabled ? controller.autonomy : "SUGGEST",
      allowedActions: controller.allowedActions,
      minConfidence: controller.minConfidence,
      planCap: kase.tenant?.plan?.defaultAutonomyCap,
      tenantCap: kase.tenant?.aiAutonomyCap ?? "AUTO_CONTAIN",
      rulebook,
      // Level 0 is decided as if allowed and recorded as shadow below.
      ladder: level != null && level > 0 ? { level } : null,
      modelCap,
      manipulated: manipulated ? { reason: report.injection.map((f) => f.ref).slice(0, 3).join(", ") } : null,
      targetUnknown,
      endpointCriticality: endpoint?.criticality,
      autoActionsLastHour,
      maxAutoActionsPerHour: settings.maxAutoActionsPerHour,
    });

    if (level === 0) {
      // What the AI would have done, kept for the comparison at close.
      await recordResponseAction({
        caseId,
        actionType: proposed.action,
        target,
        source: "ai",
        status: "SHADOW",
        rationale: `${proposed.rationale} (${proposed.urgency})`,
        confidence: output.confidence,
        policyReason: `Shadow mode: would have been ${decision.status.toLowerCase().replace("_", " ")} — ${decision.reason}`,
        aiRunId: runId,
        requestedById: opts.requestedBy?.id,
        parameters: { ladderLevel: "0" },
        decision,
      });
      statuses.push({ action: proposed.action, target, status: "SHADOW", reason: decision.reason });
      continue;
    }

    const action = await recordResponseAction({
      caseId,
      actionType: proposed.action,
      target,
      source: "ai",
      status: decision.status === "EXECUTED" ? "PENDING_APPROVAL" : decision.status,
      rationale: `${proposed.rationale} (${proposed.urgency})`,
      confidence: output.confidence,
      policyReason: decision.reason,
      aiRunId: runId,
      requestedById: opts.requestedBy?.id,
      ...(level != null ? { parameters: { ladderLevel: String(level) } } : {}),
      decision,
    });
    if (decision.status === "EXECUTED") {
      await db.responseAction.update({ where: { id: action.id }, data: { decidedAt: new Date() } });
      const done = await performResponseAction(action.id, { name: `${agentName} (auto-contain)` });
      // Level 3: the client hears straight away, with how to undo it.
      if (level === 3 && done.status === "EXECUTED" && kase.tenantId) {
        const admins = await db.user.findMany({ where: { tenantId: kase.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
        const watchers = await db.caseWatcher.findMany({ where: { caseId }, select: { userId: true } });
        await notify([...admins.map((a) => a.id), ...watchers.map((w) => w.userId)], {
          kind: "ai",
          title: `HELIOS acted: ${ACTION_LABEL[proposed.action]} ${target}`,
          body: `On "${kase.title}". It can be rolled back from the case.`,
          caseId,
          actorName: agentName,
        });
      }
    } else if (decision.status === "PENDING_APPROVAL") {
      pendingLabels.push(`${ACTION_LABEL[proposed.action]} ${target}`);
    }
    statuses.push({ action: proposed.action, target, status: decision.status, reason: decision.reason });
  }

  const injection = report.injection;
  if (injection.length) {
    await db.timelineEntry.create({
      data: { caseId, occurredAt: new Date(), actor: agentName, action: "ai.manipulation_suspected", detail: `Evidence contains text aimed at the AI: ${injection.slice(0, 3).map((f) => `${f.ref} "${f.excerpt}"`).join("; ")}`, evidence: { runId, injection: JSON.parse(JSON.stringify(injection)) } },
    });
  }

  if (silent) {
    await db.timelineEntry.create({
      data: { caseId, occurredAt: new Date(), actor: agentName, action: "ai.shadow_recorded", detail: "AI analysis recorded in shadow mode; it's shown when the case is closed", evidence: { runId } },
    });
    return { statuses, silent };
  }

  // Severity only ratchets up; the analyst decides on any downgrade.
  const aiSeverity: CaseSeverity = SEVERITY_FROM_AI[output.severity];
  const escalate = severityRank(aiSeverity) > severityRank(kase.severity);
  await db.case.update({
    where: { id: caseId },
    data: {
      tier: Math.max(kase.tier, output.escalation_tier),
      ...(escalate ? { severity: aiSeverity } : {}),
      ...(kase.status === "OPEN" ? { status: "TRIAGING" } : {}),
    },
  });
  await markCaseAfterResponse(caseId);

  const verdictLabel = output.verdict.replace("_", " ");
  const body = [
    `**Verdict:** ${verdictLabel} · **Confidence:** ${Math.round(output.confidence * 100)}% · **Suggested tier:** ${output.escalation_tier}${escalate ? ` · **Severity raised to ${aiSeverity.toLowerCase()}**` : ""}`,
    "",
    output.summary,
    output.key_findings.length ? `\n**Key findings**\n${output.key_findings.map((f) => `- ${f.finding} _(${f.evidence.join(", ")})_`).join("\n")}` : "",
    statuses.length ? `\n**Containment**\n${statuses.map((s) => `- ${ACTION_LABEL[s.action]} \`${s.target}\` — ${s.status.toLowerCase().replace("_", " ")}: ${s.reason}`).join("\n")}` : "",
    output.analyst_next_steps.length ? `\n**For the analyst**\n${output.analyst_next_steps.map((s) => `- ${s}`).join("\n")}` : "",
    report.notes.length ? `\n_Grounding check: ${report.notes.join("; ")}_` : "",
  ]
    .filter(Boolean)
    .join("\n");
  await db.caseComment.create({ data: { caseId, authorName: `${agentName} · ${engine}`, kind: "ai", body, internal: true } });
  await db.timelineEntry.create({
    data: { caseId, occurredAt: new Date(), actor: agentName, action: "ai.triage_completed", detail: `${verdictLabel} at ${Math.round(output.confidence * 100)}% confidence; ${statuses.length} containment recommendation(s)`, evidence: { runId } },
  });

  // Hand-off: the queue for the suggested tier, and approvers when needed.
  const tier = Math.max(kase.tier, output.escalation_tier);
  const worthPaging = output.verdict !== "benign" && (tier >= 2 || severityRank(kase.severity) >= severityRank("HIGH"));
  if (worthPaging && opts.trigger === "auto") {
    const roles = tier >= 3 ? (["INCIDENT_RESPONDER", "SOC_MANAGER"] as const) : tier === 2 ? (["ANALYST"] as const) : (["TRIAGE_ANALYST"] as const);
    await notify(await staffFor([...roles], kase.domain), {
      kind: "ai",
      title: `AI triaged: ${kase.title}`,
      body: `${verdictLabel}, ${Math.round(output.confidence * 100)}% confidence — tier ${tier} queue`,
      caseId,
      actorName: agentName,
    });
  }
  if (pendingLabels.length) {
    await notify(await approversFor(caseId), {
      kind: "approval",
      title: `Approval needed on ${kase.title}`,
      body: pendingLabels.slice(0, 4).join(", "),
      caseId,
      actorName: agentName,
    }, { exclude: opts.requestedBy?.id });
  }
  return { statuses, silent };
}

export async function aiSpend(since: Date) {
  const runs = await db.aiRun.findMany({ where: { createdAt: { gte: since } }, select: { model: true, inputTokens: true, outputTokens: true } });
  return aiCostOf(runs);
}
