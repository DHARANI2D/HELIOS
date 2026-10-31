import type { Case, PlaybookActionType, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { ACTION_LABEL } from "@/lib/response/labels";
import { renderTemplate } from "@/lib/playbooks/trigger";
import { dispatchAction, type DispatchResult } from "@/lib/integrations/dispatch";
import { dispatchChatMessage } from "@/lib/integrations/chat";
import { humanRulebookGate } from "@/lib/rulebook/service";
import { parsePurgeTarget, purgeTargetOfCase } from "@/lib/response/targets";

export { ACTION_LABEL };

// The one place a response action actually happens, whether a playbook, an
// AI agent (after the policy gate) or an analyst asked for it. Effects on
// client systems go through the tenant's response connector. With no
// connector the action is "manual": nothing is claimed as done, the endpoint
// inventory isn't touched, and it waits for an analyst to carry it out in
// the tool's own console and mark it done. Effects HELIOS owns — agent
// revocation, attaching telemetry — happen here directly.

export interface ActionResult {
  action: string;
  actionType: string;
  // manual: not carried out — needs a person (no connector for this action)
  // pending: a native connector asked the vendor; not confirmed yet
  status: "succeeded" | "failed" | "manual" | "pending";
  summary: string;
  skipped?: boolean; // no-op (nothing to act on) — never counts as containment
  blocked?: boolean; // refused by the client's rulebook — nothing was done
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
  // How many people approved it (the two-person rule counts them).
  approvals?: number;
  // The response action's id: the idempotency key a connector sends.
  requestId?: string;
}

export const CONTAINMENT_ACTIONS = new Set<PlaybookActionType>([
  "ISOLATE_HOST",
  "BLOCK_IP",
  "KILL_PROCESS",
  "REVOKE_AGENT",
  "DISABLE_USER",
  "QUARANTINE_FILE",
  "BLOCK_SENDER",
  "PURGE_EMAIL",
  "RESET_PASSWORD",
]);

export const ROLLBACK_OF: Partial<Record<PlaybookActionType, PlaybookActionType>> = {
  ISOLATE_HOST: "RELEASE_HOST",
  BLOCK_IP: "UNBLOCK_IP",
  DISABLE_USER: "ENABLE_USER",
  REVOKE_AGENT: "RESTORE_AGENT",
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

// `done` describes the effect once it has happened ("Isolated FIN-07");
// `todo` the same step as an instruction ("Isolate FIN-07").
// What a connector's answer means for the action. Only a confirmed state
// succeeds; a request the vendor hasn't confirmed yet is pending (the
// verification job follows it up); a dry run did nothing.
function fromDispatch(base: Pick<ActionResult, "action" | "actionType">, d: DispatchResult, target: string, text: { done: string; todo: string }, output: Record<string, unknown>): ActionResult {
  const out = { ...output, connector: d, ...(d.pending && d.native ? { pending: [{ integrationId: d.integrationId, native: d.native, ref: d.ref, target }] } : {}) };
  if (!d.dispatched) return { ...base, status: "manual", summary: `${text.todo} — no response connector for this action; carry it out in the tool's console, then mark it done`, output: out };
  if (d.dryRun) return { ...base, status: "manual", summary: `${text.todo} — ${d.message}. Carry it out by hand, or switch the connector to live`, output: out };
  if (!d.ok) return { ...base, status: "failed", summary: `${text.todo} failed — ${d.message}`, output: out };
  if (d.pending) return { ...base, status: "pending", summary: `${text.todo}: requested — ${d.message}`, output: out };
  return { ...base, status: "succeeded", summary: `${text.done} — ${d.message}`, output: out };
}

async function viaConnector(
  base: Pick<ActionResult, "action" | "actionType">,
  kase: Case,
  req: ActionRequest,
  actionType: PlaybookActionType,
  target: string,
  text: { done: string; todo: string },
  output: Record<string, unknown>,
): Promise<ActionResult> {
  const d = await dispatchAction({ tenantId: kase.tenantId, actionType, target, caseRef: { id: kase.id, title: kase.title, severity: kase.severity }, requestId: req.requestId });
  return fromDispatch(base, d, target, text, output);
}

export async function setEndpointIsolation(kase: Pick<Case, "tenantId">, host: string, isolated: boolean, by: string) {
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

// The client's rulebook binds every path that acts — AI agents, analysts and
// playbooks — so its hard rules are checked here, against the latest active
// version, at the moment of acting: a never-isolate asset, a protected
// account, an action the client forbids, or too few approvals.
async function refusal(base: Pick<ActionResult, "action" | "actionType">, kase: Case, req: ActionRequest, target: string): Promise<ActionResult | null> {
  const gate = await humanRulebookGate({ tenantId: kase.tenantId, actionType: req.actionType, target, severity: kase.severity, fresh: true });
  if (!gate.allowed) return { ...base, status: "failed", blocked: true, summary: `Not done — ${gate.reason} (rulebook v${gate.version})`, output: { target, rulebookVersion: gate.version } };
  if (gate.approvals > (req.approvals ?? 1)) {
    return { ...base, status: "failed", blocked: true, summary: `Not done — ${gate.reason}; it has ${req.approvals ?? 1} (rulebook v${gate.version})`, output: { target, rulebookVersion: gate.version } };
  }
  return null;
}

export async function executeAction(req: ActionRequest, kase: Case, ctx: ActionContext, actor = "helios"): Promise<ActionResult> {
  const base = { action: req.name, actionType: req.actionType };
  const p = req.params;

  switch (req.actionType) {
    case "BLOCK_IP":
    case "UNBLOCK_IP": {
      const block = req.actionType === "BLOCK_IP";
      const candidates = p.ip ? [p.ip] : block ? ctx.ips : [];
      if (candidates.length === 0) {
        return { ...base, status: "succeeded", skipped: true, summary: block ? "No public IPs linked to this case — nothing to block" : "No IP given" };
      }
      const refused = block ? (await Promise.all(candidates.map((ip) => refusal(base, kase, req, ip)))).filter((r): r is ActionResult => !!r) : [];
      const ips = candidates.filter((_, i) => !refused.some((r) => r.output?.target === candidates[i]));
      if (ips.length === 0) return refused.length === 1 ? refused[0] : { ...base, status: "failed", blocked: true, summary: refused.map((r) => r.summary).join("; ") };
      // The shared indicator store doubles as the blocklist feed firewalls can
      // pull (Threat Intelligence → blocklist); the connector, if any, pushes
      // the block to the client's firewall directly.
      for (const ip of ips) await setIndicatorBlocked("IP", ip, block);
      const results = await Promise.all(ips.map((ip) => dispatchAction({ tenantId: kase.tenantId, actionType: req.actionType, target: ip, caseRef: { id: kase.id, title: kase.title, severity: kase.severity }, requestId: req.requestId ? `${req.requestId}:${ip}` : undefined })));
      const listed = `${block ? "Added" : "Removed"} ${ips.join(", ")} ${block ? "to" : "from"} the HELIOS blocklist feed`;
      if (ips.length === 1) return fromDispatch(base, results[0], ips[0], { done: listed, todo: `${listed}; ${block ? "block" : "unblock"} ${ips[0]} on the client's firewall` }, { ips, connectors: results });
      const failed = results.find((r) => r.dispatched && !r.ok);
      if (results.every((r) => !r.dispatched)) {
        return { ...base, status: "manual", summary: `${listed}; no firewall connector — ${block ? "block" : "unblock"} it on the client's firewall (or confirm it pulls the feed), then mark it done`, output: { ips, connectors: results } };
      }
      if (failed) return { ...base, status: "failed", summary: `${listed}, but the firewall connector failed — ${failed.message}`, output: { ips, connectors: results } };
      const waiting = results.filter((r) => r.pending && r.native);
      if (waiting.length) {
        return { ...base, status: "pending", summary: `${listed}; waiting for the connector to confirm`, output: { ips, connectors: results, pending: waiting.map((r, i) => ({ integrationId: r.integrationId, native: r.native, ref: r.ref, target: ips[i] })) } };
      }
      return { ...base, status: "succeeded", summary: `${listed} and ${results.find((r) => r.ok)?.message}`, output: { ips, connectors: results } };
    }

    case "ISOLATE_HOST":
    case "RELEASE_HOST": {
      const isolate = req.actionType === "ISOLATE_HOST";
      const host = p.host ?? ctx.host;
      if (!host) {
        return { ...base, status: "succeeded", skipped: true, summary: "No host identified on this case — nothing to isolate" };
      }
      if (isolate) {
        const no = await refusal(base, kase, req, host);
        if (no) return no;
      }
      const result = await viaConnector(base, kase, req, req.actionType, host, { done: `${isolate ? "Isolated" : "Released"} ${host}`, todo: `${isolate ? "Isolate" : "Release"} ${host}` }, { host });
      // Only a confirmed isolation changes the endpoint inventory.
      if (result.status === "succeeded") await setEndpointIsolation(kase, host, isolate, actor);
      return result;
    }

    case "DISABLE_USER":
    case "ENABLE_USER": {
      const user = p.user ?? ctx.user;
      if (!user) return { ...base, status: "succeeded", skipped: true, summary: "No account identified on this case" };
      const disable = req.actionType === "DISABLE_USER";
      if (disable) {
        const no = await refusal(base, kase, req, user);
        if (no) return no;
      }
      return viaConnector(base, kase, req, req.actionType, user, { done: `${disable ? "Disabled" : "Re-enabled"} account ${user}`, todo: `${disable ? "Disable" : "Re-enable"} account ${user}` }, { user });
    }

    case "QUARANTINE_FILE": {
      const hash = p.hash ?? p.file;
      if (!hash) return { ...base, status: "succeeded", skipped: true, summary: "No file identified on this case" };
      const no = await refusal(base, kase, req, hash);
      if (no) return no;
      if (/^[a-f0-9]{32,64}$/i.test(hash)) await setIndicatorBlocked("FILE_HASH", hash.toLowerCase(), true);
      const short = hash.length > 20 ? `${hash.slice(0, 16)}…` : hash;
      return viaConnector(base, kase, req, "QUARANTINE_FILE", hash, { done: `Quarantined ${short}`, todo: `Quarantine ${short}` }, { hash });
    }

    case "BLOCK_SENDER": {
      const sender = p.sender;
      if (!sender) return { ...base, status: "succeeded", skipped: true, summary: "No sender identified on this case" };
      const no = await refusal(base, kase, req, sender);
      if (no) return no;
      await setIndicatorBlocked(sender.includes("@") ? "EMAIL_ADDRESS" : "DOMAIN", sender.toLowerCase(), true);
      return viaConnector(base, kase, req, "BLOCK_SENDER", sender, { done: `Blocked sender ${sender}`, todo: `Block sender ${sender}` }, { sender });
    }

    case "PURGE_EMAIL": {
      // "<message-id> to a@x, b@y": from the request, or the email case itself.
      const target = p.message ?? purgeTargetOfCase(kase.metadata);
      if (!target) return { ...base, status: "succeeded", skipped: true, summary: "No message id and recipients on this case" };
      const parsed = parsePurgeTarget(target);
      if (!parsed) return { ...base, status: "failed", summary: `Not done — "${target.slice(0, 120)}" isn't a message: use "<message-id> to recipient@example.com, …"` };
      const no = await refusal(base, kase, req, target);
      if (no) return no;
      const n = parsed.recipients.length;
      return viaConnector(base, kase, req, "PURGE_EMAIL", target, { done: `Removed message ${parsed.messageId} from ${n} mailbox${n === 1 ? "" : "es"}`, todo: `Remove message ${parsed.messageId} from ${parsed.recipients.join(", ")}` }, { messageId: parsed.messageId, recipients: parsed.recipients });
    }

    case "RESET_PASSWORD": {
      const user = p.user ?? ctx.user;
      if (!user) return { ...base, status: "succeeded", skipped: true, summary: "No account identified on this case" };
      const no = await refusal(base, kase, req, user);
      if (no) return no;
      return viaConnector(base, kase, req, "RESET_PASSWORD", user, { done: `Reset the password of ${user} and ended its sessions`, todo: `Reset the password of ${user} (change required at next sign-in) and end its sessions` }, { user });
    }

    case "KILL_PROCESS": {
      const process = p.process;
      const host = p.host ?? ctx.host;
      if (!process || !host) return { ...base, status: "succeeded", skipped: true, summary: "No process and host identified on this case" };
      const no = await refusal(base, kase, req, process);
      if (no) return no;
      return viaConnector(base, kase, req, "KILL_PROCESS", `${host}:${process}`, { done: `Terminated ${process} on ${host}`, todo: `Terminate ${process} on ${host}` }, { process, host });
    }

    case "REVOKE_AGENT":
    case "RESTORE_AGENT": {
      const agentId = p.agentId ?? (kase.sourceType === "AGENT_GOVERNANCE" ? kase.sourceRef : null);
      if (!agentId) {
        return { ...base, status: "succeeded", skipped: true, summary: "Case is not tied to an AI agent — skipped" };
      }
      const revoke = req.actionType === "REVOKE_AGENT";
      if (revoke) {
        const no = await refusal(base, kase, req, agentId);
        if (no) return no;
      }
      const agent = await db.agent.update({
        where: { id: agentId },
        data: revoke ? { status: "REVOKED", trust: 0, level: 0, mode: "ISOLATED" } : { status: "ACTIVE", trust: 100, level: 10, mode: "FULL_ACCESS" },
      });
      return { ...base, status: "succeeded", summary: `${revoke ? "Revoked" : "Restored"} agent ${agent.name}`, output: { agentId: agent.id, status: agent.status } };
    }

    case "COLLECT_LOGS": {
      // Pull related telemetry (same host or user, ±window) into the case.
      const windowMinutes = Number(p.windowMinutes ?? 60);
      const host = p.host ?? ctx.host;
      const or: Prisma.SecurityEventWhereInput[] = [];
      if (host) or.push({ hostName: host });
      if (ctx.user) or.push({ userName: ctx.user });
      if (or.length === 0) {
        return { ...base, status: "succeeded", skipped: true, summary: "No host or user on this case to collect telemetry for" };
      }
      const no = await refusal(base, kase, req, host ?? ctx.user!);
      if (no) return no;
      const from = new Date(kase.createdAt.getTime() - windowMinutes * 60_000);
      const to = new Date(kase.createdAt.getTime() + windowMinutes * 60_000);
      const { count } = await db.securityEvent.updateMany({
        where: { caseId: null, tenantId: kase.tenantId, OR: or, timestamp: { gte: from, lte: to } },
        data: { caseId: kase.id },
      });
      return { ...base, status: "succeeded", summary: `Attached ${count} related events to the case`, output: { attached: count } };
    }

    case "NOTIFY_SLACK": {
      const message = renderTemplate(p.message ?? "HELIOS case update: {{case.title}}", ctx.vars);
      const sent = await dispatchChatMessage(kase.tenantId, message);
      return sent.sent
        ? { ...base, status: "succeeded", summary: `${sent.message}: "${message}"`, output: { message } }
        : { ...base, status: "manual", summary: `Not sent — ${sent.message}`, output: { message } };
    }

    case "CREATE_TICKET": {
      const title = renderTemplate(p.title ?? "{{case.title}}", ctx.vars);
      // The connector (Jira, ServiceNow or your automation) opens the ticket
      // and answers with its id; HELIOS never invents one.
      return viaConnector(base, kase, req, "CREATE_TICKET", title, { done: `Ticket requested: "${title}"`, todo: `Open a ticket "${title}"` }, { title });
    }
  }
}
