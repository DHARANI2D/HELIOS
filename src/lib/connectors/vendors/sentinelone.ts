import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx, Execution, NativeConnector, Preflight } from "@/lib/connectors/types";

// SentinelOne: disconnect an agent from the network and reconnect it, and
// block a file hash from running. Disconnects are confirmed when the
// agent's networkStatus reads "disconnected" (or "connected"). A
// service-user API token scoped to the client's site.
//
// File blocks are blocklist entries (POST /restrictions, type black_hash),
// one per OS type, scoped to the client's site, confirmed by reading the
// blocklist back. SentinelOne's API reference is behind its console; this is
// written against the Cortex XSOAR SentinelOne-V2 integration
// (demisto/content), which sends a SHA-1 as value and a SHA-256 as
// sha256Value. Check it against a lab console before relying on it.

const base = (ctx: ConnectorCtx) => {
  const url = ctx.config.consoleUrl?.replace(/\/+$/, "");
  if (!url) throw new ConnectorError("Set the management console URL", null);
  return `${url}/web/api/v2.1`;
};

function auth(ctx: ConnectorCtx) {
  if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
  return { authorization: `ApiToken ${ctx.secrets.apiToken}` };
}

const OS_TYPES = ["windows", "macos", "linux"] as const;

interface Restriction {
  id: string;
  value?: string;
  sha256Value?: string;
  osType?: string;
}

function hashKind(value: string) {
  if (/^[a-f0-9]{64}$/i.test(value)) return "sha256" as const;
  if (/^[a-f0-9]{40}$/i.test(value)) return "sha1" as const;
  return null;
}

// The site's blocklist entries for a hash, by OS type.
async function blocked(ctx: ConnectorCtx, hash: string) {
  const siteId = ctx.config.siteId;
  if (!siteId) throw new ConnectorError("Set the site ID file blocks apply to", null);
  const q = new URLSearchParams({ siteIds: siteId, type: "black_hash", value__contains: hash.toLowerCase(), limit: "100" });
  const res = await ctx.http<{ data: Restriction[] }>(`${base(ctx)}/restrictions?${q}`, { headers: auth(ctx) });
  const h = hash.toLowerCase();
  const mine = (res.data.data ?? []).filter((r) => r.value?.toLowerCase() === h || r.sha256Value?.toLowerCase() === h);
  return new Set(mine.map((r) => (r.osType ?? "").toLowerCase()));
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
  actions: ["ISOLATE_HOST", "RELEASE_HOST", "QUARANTINE_FILE"],
  docs: "Management API v2.1: GET /agents, POST /agents/actions/disconnect, POST /agents/actions/connect, GET/POST /restrictions (black_hash)",
  fields: [
    { key: "consoleUrl", label: "Management console URL", required: true, placeholder: "https://usea1-acme.sentinelone.net" },
    { key: "apiToken", label: "API token", secret: true, required: true },
    { key: "siteId", label: "Site ID", hint: "The client's site, for file blocks (blocklist entries are scoped to it)" },
  ],

  async check(ctx) {
    await ctx.http(`${base(ctx)}/agents?limit=1`, { headers: auth(ctx) });
    return { ok: true, message: "Signed in to SentinelOne and read the agent list" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    if (action === "QUARANTINE_FILE") {
      if (!hashKind(target)) return { ok: false, reason: `${target} isn't a SHA-256 or SHA-1 hash (SentinelOne's blocklist takes those)` };
      const have = await blocked(ctx, target);
      return { ok: true, resolved: { id: target.toLowerCase(), name: target }, alreadyDone: OS_TYPES.every((os) => have.has(os)) };
    }
    const res = await ctx.http<{ data: Agent[] }>(`${base(ctx)}/agents?computerName=${encodeURIComponent(target)}`, { headers: auth(ctx) });
    const agents = res.data.data ?? [];
    if (!agents.length) return { ok: false, reason: `no SentinelOne agent named ${target}` };
    if (agents.length > 1) return { ok: false, reason: `${agents.length} SentinelOne agents are named ${target}; isolate the right one by hand` };
    const a = agents[0];
    const isolate = action === "ISOLATE_HOST";
    return { ok: true, resolved: { id: a.id, name: a.computerName, state: a.networkStatus }, alreadyDone: isolate ? a.networkStatus === "disconnected" : a.networkStatus === "connected" };
  },

  async execute({ action, target, ctx, comment, idempotencyKey }, resolved): Promise<Execution> {
    if (action === "QUARANTINE_FILE") {
      const hash = target.toLowerCase();
      const kind = hashKind(hash)!;
      const have = await blocked(ctx, hash);
      const add = OS_TYPES.filter((os) => !have.has(os));
      for (const osType of add) {
        await ctx.http(`${base(ctx)}/restrictions`, {
          headers: auth(ctx),
          json: {
            data: { value: kind === "sha1" ? hash : "", sha256Value: kind === "sha256" ? hash : "", source: "HELIOS", osType, type: "black_hash", description: `${comment} [HELIOS ${idempotencyKey}]`.slice(0, 500) },
            filter: { siteIds: [ctx.config.siteId] },
          },
        });
      }
      return { ref: { hash, siteId: ctx.config.siteId ?? "" }, confirmed: false, message: `Added ${hash} to the site's blocklist for ${add.join(", ") || "no new"} OS types` };
    }
    const path = action === "ISOLATE_HOST" ? "disconnect" : "connect";
    const res = await ctx.http<{ data: { affected: number } }>(`${base(ctx)}/agents/actions/${path}`, { headers: auth(ctx), json: { filter: { ids: [resolved.id] } } });
    if (!res.data.data?.affected) throw new ConnectorError(`SentinelOne didn't ${path} ${resolved.name} (0 agents affected)`, null);
    return { ref: { agentId: resolved.id, computerName: resolved.name }, confirmed: false, message: `${path === "disconnect" ? "Network disconnect" : "Reconnect"} sent to ${resolved.name}` };
  },

  async verify({ action, ctx }, ref) {
    if (action === "QUARANTINE_FILE") {
      const have = await blocked(ctx, ref.hash);
      const missing = OS_TYPES.filter((os) => !have.has(os));
      return missing.length ? { state: "pending", message: `SentinelOne's blocklist doesn't list ${ref.hash} for ${missing.join(", ")} yet` } : { state: "confirmed", message: `SentinelOne blocks ${ref.hash} on Windows, macOS and Linux in the site` };
    }
    const res = await ctx.http<{ data: Agent[] }>(`${base(ctx)}/agents?ids=${encodeURIComponent(ref.agentId)}`, { headers: auth(ctx) });
    const a = res.data.data?.[0];
    if (!a) return { state: "failed", message: `SentinelOne no longer lists ${ref.computerName}` };
    const want = action === "ISOLATE_HOST" ? "disconnected" : "connected";
    if (a.networkStatus === want) return { state: "confirmed", message: `SentinelOne shows ${ref.computerName} ${want}` };
    return { state: "pending", message: `SentinelOne shows ${ref.computerName} ${a.networkStatus}` };
  },
};
