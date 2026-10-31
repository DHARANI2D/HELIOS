import { ConnectorError, microsoftToken, odata } from "@/lib/connectors/http";
import type { ConnectorCtx, Execution, NativeConnector, Preflight, VendorRef } from "@/lib/connectors/types";

// Microsoft Defender for Endpoint: isolate and release devices (machine
// actions, confirmed when the action reports Succeeded), collect a device's
// investigation package, and block files and IPs through custom indicators.
// An app registration with Machine.Isolate, Machine.CollectForensics,
// Machine.Read.All and Ti.ReadWrite.All (application permissions) is enough.
//
// The investigation package (POST /api/machines/{id}/collectInvestigationPackage,
// then GET /api/machineactions/{id} until Succeeded, then
// /api/machineactions/{id}/getPackageUri for a short-lived download link) is
// written against Microsoft's own Get-MDEInvestigationPackage playbook in the
// Azure-Sentinel repository; learn.microsoft.com wasn't reachable here.

const SCOPE = "https://api.securitycenter.microsoft.com/.default";
const base = (ctx: ConnectorCtx) => (ctx.config.apiBase || "https://api.securitycenter.microsoft.com").replace(/\/+$/, "");

async function auth(ctx: ConnectorCtx) {
  return { authorization: `Bearer ${await microsoftToken(ctx, SCOPE)}` };
}

interface Machine {
  id: string;
  computerDnsName: string;
  healthStatus?: string;
}

interface MachineAction {
  id: string;
  type: string;
  status: "Pending" | "InProgress" | "Succeeded" | "Failed" | "TimeOut" | "Cancelled" | string;
  machineId?: string;
}

interface Indicator {
  id: string | number;
  indicatorValue: string;
  action: string;
}

async function findMachine(ctx: ConnectorCtx, host: string): Promise<Preflight> {
  const headers = await auth(ctx);
  const q = (filter: string) => ctx.http<{ value: Machine[] }>(`${base(ctx)}/api/machines?$filter=${encodeURIComponent(filter)}`, { headers });
  let found = (await q(`computerDnsName eq '${odata(host.toLowerCase())}'`)).data.value;
  // Devices report their FQDN; a bare hostname matches its first label.
  if (!found.length && !host.includes(".")) found = (await q(`startswith(computerDnsName,'${odata(host.toLowerCase())}.')`)).data.value;
  if (!found.length) return { ok: false, reason: `no device named ${host} in Defender` };
  if (found.length > 1) return { ok: false, reason: `${found.length} devices match ${host} in Defender; isolate the right one by hand` };
  const m = found[0];
  return { ok: true, resolved: { id: m.id, name: m.computerDnsName, state: m.healthStatus } };
}

function hashType(value: string) {
  if (/^[a-f0-9]{64}$/i.test(value)) return "FileSha256";
  if (/^[a-f0-9]{40}$/i.test(value)) return "FileSha1";
  if (/^[a-f0-9]{32}$/i.test(value)) return "FileMd5";
  return null;
}

async function findIndicator(ctx: ConnectorCtx, value: string): Promise<Indicator | null> {
  const res = await ctx.http<{ value: Indicator[] }>(`${base(ctx)}/api/indicators?$filter=${encodeURIComponent(`indicatorValue eq '${odata(value)}'`)}`, { headers: await auth(ctx) });
  return res.data.value.find((i) => /block/i.test(i.action)) ?? null;
}

export const defender: NativeConnector = {
  key: "defender_endpoint",
  label: "Microsoft Defender for Endpoint",
  tools: ["defender_endpoint_p2", "defender_business"],
  actions: ["ISOLATE_HOST", "RELEASE_HOST", "COLLECT_FORENSICS", "QUARANTINE_FILE", "BLOCK_IP", "UNBLOCK_IP"],
  docs: "https://learn.microsoft.com/defender-endpoint/api/isolate-machine · /unisolate-machine · /collect-investigation-package · /get-package-sas-uri · /get-machineaction-object · /post-ti-indicator",
  fields: [
    { key: "tenantId", label: "Directory (tenant) ID", required: true },
    { key: "clientId", label: "Application (client) ID", required: true },
    { key: "clientSecret", label: "Client secret", secret: true, required: true },
    { key: "apiBase", label: "API host", placeholder: "https://api.securitycenter.microsoft.com", hint: "Leave blank for the global endpoint, or set the regional or api.security.microsoft.com host" },
    { key: "isolationType", label: "Isolation type", placeholder: "Full", hint: "Full or Selective (Selective keeps Outlook, Teams and Skype working)" },
  ],

  async check(ctx) {
    await ctx.http(`${base(ctx)}/api/machines?$top=1`, { headers: await auth(ctx) });
    return { ok: true, message: "Signed in to Defender for Endpoint and read the device list" };
  },

  async preflight({ action, target, ctx }) {
    if (action === "ISOLATE_HOST" || action === "RELEASE_HOST" || action === "COLLECT_FORENSICS") return findMachine(ctx, target);
    if (action === "QUARANTINE_FILE") {
      if (!hashType(target)) return { ok: false, reason: `${target} isn't a SHA-256, SHA-1 or MD5 hash` };
      const existing = await findIndicator(ctx, target);
      return { ok: true, resolved: { id: existing ? String(existing.id) : target, name: target }, alreadyDone: !!existing };
    }
    if (action === "BLOCK_IP" || action === "UNBLOCK_IP") {
      const existing = await findIndicator(ctx, target);
      if (action === "UNBLOCK_IP") return { ok: true, resolved: { id: existing ? String(existing.id) : "", name: target }, alreadyDone: !existing };
      return { ok: true, resolved: { id: existing ? String(existing.id) : target, name: target }, alreadyDone: !!existing };
    }
    return { ok: false, reason: `Defender connector doesn't do ${action}` };
  },

  async execute({ action, target, ctx, comment, idempotencyKey }, resolved): Promise<Execution> {
    const headers = await auth(ctx);
    const note = `${comment} [HELIOS ${idempotencyKey}]`.slice(0, 1000);
    if (action === "ISOLATE_HOST" || action === "RELEASE_HOST" || action === "COLLECT_FORENSICS") {
      const path = action === "ISOLATE_HOST" ? "isolate" : action === "RELEASE_HOST" ? "unisolate" : "collectInvestigationPackage";
      const body = action === "ISOLATE_HOST" ? { Comment: note, IsolationType: ctx.config.isolationType === "Selective" ? "Selective" : "Full" } : { Comment: note };
      const res = await ctx.http<MachineAction | { error?: { code?: string } }>(`${base(ctx)}/api/machines/${encodeURIComponent(resolved.id)}/${path}`, { headers, json: body, expect: [400] });
      if (res.status === 400) {
        // An identical request already running is the one to follow.
        const code = (res.data as { error?: { code?: string } }).error?.code ?? "";
        if (!/ActiveRequestAlreadyExists/i.test(code)) throw new ConnectorError(`Defender refused the request: ${JSON.stringify(res.data).slice(0, 200)}`, 400);
        const type = action === "ISOLATE_HOST" ? "Isolate" : action === "RELEASE_HOST" ? "Unisolate" : "CollectInvestigationPackage";
        const running = await ctx.http<{ value: MachineAction[] }>(`${base(ctx)}/api/machineactions?$filter=${encodeURIComponent(`machineId eq '${odata(resolved.id)}' and type eq '${type}'`)}`, { headers });
        const latest = running.data.value.find((a) => a.status === "Pending" || a.status === "InProgress");
        if (!latest) throw new ConnectorError("Defender says a request is already running but none was found", 400);
        return { ref: { machineActionId: latest.id, machineId: resolved.id }, confirmed: false, message: `${type} already requested in Defender (action ${latest.id})` };
      }
      const a = res.data as MachineAction;
      const what = action === "ISOLATE_HOST" ? "Isolation" : action === "RELEASE_HOST" ? "Release" : "Investigation package";
      // A package is only done once it can be downloaded: verify fetches the link.
      return { ref: { machineActionId: a.id, machineId: resolved.id }, confirmed: action !== "COLLECT_FORENSICS" && a.status === "Succeeded", message: `${what} requested in Defender (action ${a.id}, ${a.status})` };
    }
    if (action === "UNBLOCK_IP") {
      await ctx.http(`${base(ctx)}/api/indicators/${encodeURIComponent(resolved.id)}`, { method: "DELETE", headers, expect: [404] });
      return { ref: { indicatorValue: target }, confirmed: false, message: `Removed the Defender indicator for ${target}` };
    }
    const isFile = action === "QUARANTINE_FILE";
    const res = await ctx.http<Indicator>(`${base(ctx)}/api/indicators`, {
      headers,
      json: {
        indicatorValue: target,
        indicatorType: isFile ? hashType(target) : "IpAddress",
        action: isFile ? "BlockAndRemediate" : "Block",
        title: `HELIOS: ${isFile ? "block file" : "block IP"} ${target}`.slice(0, 200),
        description: note,
        severity: "High",
        generateAlert: true,
      },
    });
    return { ref: { indicatorId: String(res.data.id), indicatorValue: target }, confirmed: false, message: `Defender indicator ${res.data.id} created (${isFile ? "block and remediate" : "block"})` };
  },

  async verify({ action, ctx }, ref: VendorRef) {
    if (ref.machineActionId) {
      const res = await ctx.http<MachineAction>(`${base(ctx)}/api/machineactions/${encodeURIComponent(ref.machineActionId)}`, { headers: await auth(ctx) });
      const s = res.data.status;
      if (s === "Succeeded" && action === "COLLECT_FORENSICS") {
        // The link is a short-lived signed URL; the package stays in the
        // device's Action center in the Defender portal.
        const uri = await ctx.http<{ value?: string }>(`${base(ctx)}/api/machineactions/${encodeURIComponent(ref.machineActionId)}/getPackageUri`, { headers: await auth(ctx) });
        if (!uri.data.value) return { state: "pending", message: "Defender collected the package but has no download link yet" };
        return { state: "confirmed", message: `Defender collected the investigation package. Download (a short-lived link; the package stays in the device's Action center): ${uri.data.value}` };
      }
      if (s === "Succeeded") return { state: "confirmed", message: `Defender reports the ${res.data.type.toLowerCase()} succeeded` };
      if (s === "Pending" || s === "InProgress") return { state: "pending", message: `Defender action ${ref.machineActionId} is ${s === "Pending" ? "waiting for the device" : "in progress"}` };
      return { state: "failed", message: `Defender action ${ref.machineActionId} ended ${s}` };
    }
    const existing = await findIndicator(ctx, ref.indicatorValue);
    if (action === "UNBLOCK_IP") return existing ? { state: "pending", message: "The indicator is still listed" } : { state: "confirmed", message: `No Defender block indicator left for ${ref.indicatorValue}` };
    return existing ? { state: "confirmed", message: `Defender indicator ${existing.id} is in place` } : { state: "failed", message: "The indicator wasn't found after creating it" };
  },
};
