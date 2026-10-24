import type { Case, PlaybookActionType, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { renderTemplate } from "@/lib/playbooks/trigger";
import { dispatchAction, type DispatchResult } from "@/lib/integrations/dispatch";

// The one place a response action actually happens, whether a playbook, an
// AI agent (after the policy gate) or an analyst asked for it. Effects inside
// HELIOS are real — the blocklist feed, the endpoint inventory's isolation
// state, agent revocation; effects on client systems go through the tenant's
// response connector, and are reported as simulated when there is none.

export interface ActionResult {
  action: string;
  actionType: string;
  status: "succeeded" | "failed";
  summary: string;
  simulated: boolean;
  skipped?: boolean; // no-op (nothing to act on) — never counts as containment
  output?: Record<string, unknown>;
}

export interface ActionContext {
  host?: string;
  user?: string;
  ips: string[];
  vars: Record<string, string | undefined>;
}

export interface ActionRequest {
  name: string;
  actionType: PlaybookActionType;
  params: Record<string, string | undefined>;
}

export const CONTAINMENT_ACTIONS = new Set<PlaybookActionType>([
  "ISOLATE_HOST",
  "BLOCK_IP",
  "KILL_PROCESS",
  "REVOKE_AGENT",
  "DISABLE_USER",
  "QUARANTINE_FILE",
  "BLOCK_SENDER",
]);

export const ROLLBACK_OF: Partial<Record<PlaybookActionType, PlaybookActionType>> = {
  ISOLATE_HOST: "RELEASE_HOST",
  BLOCK_IP: "UNBLOCK_IP",
  DISABLE_USER: "ENABLE_USER",
  REVOKE_AGENT: "RESTORE_AGENT",
};

export const ACTION_LABEL: Record<PlaybookActionType, string> = {
  ISOLATE_HOST: "Isolate host",
  RELEASE_HOST: "Release host",
  BLOCK_IP: "Block IP",
  UNBLOCK_IP: "Unblock IP",
  NOTIFY_SLACK: "Notify channel",
  CREATE_TICKET: "Create ticket",
  KILL_PROCESS: "Kill process",
  COLLECT_LOGS: "Collect logs",
  REVOKE_AGENT: "Revoke AI agent",
  RESTORE_AGENT: "Restore AI agent",
  DISABLE_USER: "Disable account",
  ENABLE_USER: "Re-enable account",
  QUARANTINE_FILE: "Quarantine file",
  BLOCK_SENDER: "Block sender",
};

export async function buildActionContext(kase: Case): Promise<ActionContext> {
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

export function paramsOf(parameters: Prisma.JsonValue | null | undefined): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  if (parameters && typeof parameters === "object" && !Array.isArray(parameters)) {
    for (const [k, v] of Object.entries(parameters)) {
      if (typeof v === "string") out[k] = v;
      else if (typeof v === "number") out[k] = String(v);
    }
  }
  return out;
}

function connectorSummary(base: string, d: DispatchResult) {
  if (!d.dispatched) return { summary: base, simulated: true };
  return { summary: `${base} — ${d.message}`, simulated: false };
}

async function viaConnector(
  base: Pick<ActionResult, "action" | "actionType">,
  kase: Case,
  actionType: PlaybookActionType,
  target: string,
  description: string,
  output: Record<string, unknown>,
): Promise<ActionResult> {
  const d = await dispatchAction({ tenantId: kase.tenantId, actionType, target, caseRef: { id: kase.id, title: kase.title, severity: kase.severity } });
  if (d.dispatched && !d.ok) {
    return { ...base, status: "failed", simulated: false, summary: `${description} failed — ${d.message}`, output: { ...output, connector: d } };
  }
  const { summary, simulated } = connectorSummary(description, d);
  return { ...base, status: "succeeded", simulated, summary, output: { ...output, connector: d } };
}

async function setEndpointIsolation(kase: Case, host: string, isolated: boolean, by: string) {
  const where = { tenantId: kase.tenantId, hostname: { equals: host, mode: "insensitive" as const } };
  const { count } = await db.endpoint.updateMany({
    where,
    data: isolated ? { isolated: true, isolatedAt: new Date(), isolatedBy: by } : { isolated: false, isolatedAt: null, isolatedBy: null },
  });
  if (count === 0 && isolated) {
    await db.endpoint.create({ data: { tenantId: kase.tenantId, hostname: host, isolated: true, isolatedAt: new Date(), isolatedBy: by, source: "telemetry", lastSeenAt: new Date() } });
  }
}

async function setIndicatorBlocked(type: "IP" | "EMAIL_ADDRESS" | "FILE_HASH" | "DOMAIN", value: string, blocked: boolean) {
  await db.threatIndicator.upsert({
    where: { type_value: { type, value } },
    update: { blockedAt: blocked ? new Date() : null },
    create: { type, value, providerData: {}, sources: [], expiresAt: new Date(), blockedAt: blocked ? new Date() : null },
  });
}

export async function executeAction(req: ActionRequest, kase: Case, ctx: ActionContext, actor = "helios"): Promise<ActionResult> {
  const base = { action: req.name, actionType: req.actionType };
  const p = req.params;

  switch (req.actionType) {
    case "BLOCK_IP":
    case "UNBLOCK_IP": {
      const block = req.actionType === "BLOCK_IP";
      const ips = p.ip ? [p.ip] : block ? ctx.ips : [];
      if (ips.length === 0) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: block ? "No public IPs linked to this case — nothing to block" : "No IP given" };
      }
      // A real effect inside HELIOS: the shared indicator store doubles as the
      // blocklist exported on the Threat Intelligence page.
      for (const ip of ips) await setIndicatorBlocked("IP", ip, block);
      const results = await Promise.all(ips.map((ip) => dispatchAction({ tenantId: kase.tenantId, actionType: req.actionType, target: ip, caseRef: { id: kase.id, title: kase.title, severity: kase.severity } })));
      const failed = results.find((r) => r.dispatched && !r.ok);
      const sent = results.find((r) => r.dispatched && r.ok);
      return {
        ...base,
        status: "succeeded",
        simulated: false,
        summary: `${block ? "Added" : "Removed"} ${ips.join(", ")} ${block ? "to" : "from"} the HELIOS blocklist${sent ? ` and ${sent.message}` : ""}${failed ? ` (connector: ${failed.message})` : ""}`,
        output: { ips, connectors: results },
      };
    }

    case "ISOLATE_HOST":
    case "RELEASE_HOST": {
      const isolate = req.actionType === "ISOLATE_HOST";
      const host = p.host ?? ctx.host;
      if (!host) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No host identified on this case — nothing to isolate" };
      }
      const result = await viaConnector(base, kase, req.actionType, host, `${isolate ? "Isolated" : "Released"} ${host}${p.method ? ` via ${p.method}` : ""}`, { host });
      if (result.status === "succeeded") await setEndpointIsolation(kase, host, isolate, actor);
      return result;
    }

    case "DISABLE_USER":
    case "ENABLE_USER": {
      const user = p.user ?? ctx.user;
      if (!user) return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No account identified on this case" };
      return viaConnector(base, kase, req.actionType, user, `${req.actionType === "DISABLE_USER" ? "Disabled" : "Re-enabled"} account ${user}`, { user });
    }

    case "QUARANTINE_FILE": {
      const hash = p.hash ?? p.file;
      if (!hash) return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No file identified on this case" };
      if (/^[a-f0-9]{32,64}$/i.test(hash)) await setIndicatorBlocked("FILE_HASH", hash.toLowerCase(), true);
      return viaConnector(base, kase, "QUARANTINE_FILE", hash, `Quarantined ${hash.length > 20 ? `${hash.slice(0, 16)}…` : hash} and added it to the hash blocklist`, { hash });
    }

    case "BLOCK_SENDER": {
      const sender = p.sender;
      if (!sender) return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No sender identified on this case" };
      await setIndicatorBlocked(sender.includes("@") ? "EMAIL_ADDRESS" : "DOMAIN", sender.toLowerCase(), true);
      return viaConnector(base, kase, "BLOCK_SENDER", sender, `Blocked sender ${sender}`, { sender });
    }

    case "KILL_PROCESS": {
      const process = p.process ?? "the flagged process";
      return viaConnector(base, kase, "KILL_PROCESS", `${ctx.host ?? "unknown"}:${process}`, `Terminated ${process} on ${p.host ?? ctx.host ?? "the affected host"}`, { process, host: p.host ?? ctx.host });
    }

    case "REVOKE_AGENT":
    case "RESTORE_AGENT": {
      const agentId = p.agentId ?? (kase.sourceType === "AGENT_GOVERNANCE" ? kase.sourceRef : null);
      if (!agentId) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "Case is not tied to an AI agent — skipped" };
      }
      const revoke = req.actionType === "REVOKE_AGENT";
      const agent = await db.agent.update({
        where: { id: agentId },
        data: revoke ? { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" } : { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
      });
      return { ...base, status: "succeeded", simulated: false, summary: `${revoke ? "Revoked" : "Restored"} agent ${agent.name}`, output: { agentId: agent.id, status: agent.status } };
    }

    case "COLLECT_LOGS": {
      // Pull related telemetry (same host or user, ±window) into the case.
      const windowMinutes = Number(p.windowMinutes ?? 60);
      const host = p.host ?? ctx.host;
      const or: Prisma.SecurityEventWhereInput[] = [];
      if (host) or.push({ hostName: host });
      if (ctx.user) or.push({ userName: ctx.user });
      if (or.length === 0) {
        return { ...base, status: "succeeded", simulated: false, skipped: true, summary: "No host or user on this case to collect telemetry for" };
      }
      const from = new Date(kase.createdAt.getTime() - windowMinutes * 60_000);
      const to = new Date(kase.createdAt.getTime() + windowMinutes * 60_000);
      const { count } = await db.securityEvent.updateMany({
        where: { caseId: null, tenantId: kase.tenantId, OR: or, timestamp: { gte: from, lte: to } },
        data: { caseId: kase.id },
      });
      return { ...base, status: "succeeded", simulated: false, summary: `Attached ${count} related events to the case`, output: { attached: count } };
    }

    case "NOTIFY_SLACK": {
      const message = renderTemplate(p.message ?? "HELIOS case update: {{case.title}}", ctx.vars);
      const channel = p.channel;
      const webhook = p.webhookUrl ?? process.env.SLACK_WEBHOOK_URL;
      if (!webhook) {
        return { ...base, status: "succeeded", simulated: true, summary: `Would post to ${channel ?? "Slack"}: "${message}"`, output: { channel, message } };
      }
      const res = await fetch(webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: message, channel }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`Chat webhook returned HTTP ${res.status}`);
      return { ...base, status: "succeeded", simulated: false, summary: `Posted to ${channel ?? "Slack"}: "${message}"`, output: { channel, message } };
    }

    case "CREATE_TICKET": {
      const title = renderTemplate(p.title ?? "{{case.title}}", ctx.vars);
      const project = p.project ?? "SEC";
      const ticketId = `${project}-${kase.id.slice(-6).toUpperCase()}`;
      return { ...base, status: "succeeded", simulated: true, summary: `Ticket ${ticketId}: "${title}"`, output: { ticketId, title, system: p.system ?? "jira" } };
    }
  }
}
