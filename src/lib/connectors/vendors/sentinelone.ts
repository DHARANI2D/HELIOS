import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx, NativeConnector, Preflight } from "@/lib/connectors/types";

// SentinelOne: disconnect an agent from the network and reconnect it.
// Confirmed when the agent's networkStatus reads "disconnected" (or
// "connected"). A service-user API token scoped to the client's site.

const base = (ctx: ConnectorCtx) => {
  const url = ctx.config.consoleUrl?.replace(/\/+$/, "");
  if (!url) throw new ConnectorError("Set the management console URL", null);
  return `${url}/web/api/v2.1`;
};

function auth(ctx: ConnectorCtx) {
  if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
  return { authorization: `ApiToken ${ctx.secrets.apiToken}` };
}

interface Agent {
  id: string;
  computerName: string;
  networkStatus: string; // connected | connecting | disconnected | disconnecting
}

export const sentinelone: NativeConnector = {
  key: "sentinelone",
  label: "SentinelOne",
  tools: ["sentinelone_complete", "sentinelone_core"],
  actions: ["ISOLATE_HOST", "RELEASE_HOST"],
  docs: "Management API v2.1: GET /agents, POST /agents/actions/disconnect, POST /agents/actions/connect",
  fields: [
    { key: "consoleUrl", label: "Management console URL", required: true, placeholder: "https://usea1-acme.sentinelone.net" },
    { key: "apiToken", label: "API token", secret: true, required: true },
  ],

  async check(ctx) {
    await ctx.http(`${base(ctx)}/agents?limit=1`, { headers: auth(ctx) });
    return { ok: true, message: "Signed in to SentinelOne and read the agent list" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    const res = await ctx.http<{ data: Agent[] }>(`${base(ctx)}/agents?computerName=${encodeURIComponent(target)}`, { headers: auth(ctx) });
    const agents = res.data.data ?? [];
    if (!agents.length) return { ok: false, reason: `no SentinelOne agent named ${target}` };
    if (agents.length > 1) return { ok: false, reason: `${agents.length} SentinelOne agents are named ${target}; isolate the right one by hand` };
    const a = agents[0];
    const isolate = action === "ISOLATE_HOST";
    return { ok: true, resolved: { id: a.id, name: a.computerName, state: a.networkStatus }, alreadyDone: isolate ? a.networkStatus === "disconnected" : a.networkStatus === "connected" };
  },

  async execute({ action, ctx }, resolved) {
    const path = action === "ISOLATE_HOST" ? "disconnect" : "connect";
    const res = await ctx.http<{ data: { affected: number } }>(`${base(ctx)}/agents/actions/${path}`, { headers: auth(ctx), json: { filter: { ids: [resolved.id] } } });
    if (!res.data.data?.affected) throw new ConnectorError(`SentinelOne didn't ${path} ${resolved.name} (0 agents affected)`, null);
    return { ref: { agentId: resolved.id, computerName: resolved.name }, confirmed: false, message: `${path === "disconnect" ? "Network disconnect" : "Reconnect"} sent to ${resolved.name}` };
  },

  async verify({ action, ctx }, ref) {
    const res = await ctx.http<{ data: Agent[] }>(`${base(ctx)}/agents?ids=${encodeURIComponent(ref.agentId)}`, { headers: auth(ctx) });
    const a = res.data.data?.[0];
    if (!a) return { state: "failed", message: `SentinelOne no longer lists ${ref.computerName}` };
    const want = action === "ISOLATE_HOST" ? "disconnected" : "connected";
    if (a.networkStatus === want) return { state: "confirmed", message: `SentinelOne shows ${ref.computerName} ${want}` };
    return { state: "pending", message: `SentinelOne shows ${ref.computerName} ${a.networkStatus}` };
  },
};
