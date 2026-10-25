import { ConnectorError, cachedToken } from "@/lib/connectors/http";
import type { ConnectorCtx, NativeConnector, Preflight } from "@/lib/connectors/types";

// CrowdStrike Falcon: network-contain a host and lift containment. Confirmed
// when the device's status reads "contained" (or "normal" after lifting). An
// API client with Hosts: read and write is enough. The base URL must be the
// client's own cloud (US-1, US-2, EU-1, US-GOV-1).

const base = (ctx: ConnectorCtx) => (ctx.config.baseUrl || "https://api.crowdstrike.com").replace(/\/+$/, "");

async function auth(ctx: ConnectorCtx) {
  const { clientId } = ctx.config;
  const { clientSecret } = ctx.secrets;
  if (!clientId || !clientSecret) throw new ConnectorError("Set the API client ID and secret", null);
  const token = await cachedToken(`${ctx.cacheKey}:falcon`, async () => {
    const res = await ctx.http<{ access_token: string; expires_in: number }>(`${base(ctx)}/oauth2/token`, { form: { client_id: clientId, client_secret: clientSecret } });
    return { token: res.data.access_token, expiresIn: Number(res.data.expires_in) || 1800 };
  });
  return { authorization: `Bearer ${token}` };
}

interface Device {
  device_id: string;
  hostname: string;
  status: string; // normal | containment_pending | contained | lift_containment_pending
}

async function device(ctx: ConnectorCtx, id: string): Promise<Device | null> {
  const res = await ctx.http<{ resources: Device[] }>(`${base(ctx)}/devices/entities/devices/v2?ids=${encodeURIComponent(id)}`, { headers: await auth(ctx) });
  return res.data.resources?.[0] ?? null;
}

export const crowdstrike: NativeConnector = {
  key: "crowdstrike_falcon",
  label: "CrowdStrike Falcon",
  tools: ["crowdstrike_falcon_enterprise", "crowdstrike_falcon_pro"],
  actions: ["ISOLATE_HOST", "RELEASE_HOST"],
  docs: "Falcon API: POST /devices/entities/devices-actions/v2?action_name=contain|lift_containment, GET /devices/queries/devices/v1, GET /devices/entities/devices/v2",
  fields: [
    { key: "baseUrl", label: "API base URL", placeholder: "https://api.crowdstrike.com", hint: "US-2: https://api.us-2.crowdstrike.com · EU-1: https://api.eu-1.crowdstrike.com" },
    { key: "clientId", label: "API client ID", required: true },
    { key: "clientSecret", label: "API client secret", secret: true, required: true },
  ],

  async check(ctx) {
    await ctx.http(`${base(ctx)}/devices/queries/devices/v1?limit=1`, { headers: await auth(ctx) });
    return { ok: true, message: "Signed in to Falcon and read the host list" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    const filter = encodeURIComponent(`hostname:'${target.replace(/'/g, "")}'`);
    const res = await ctx.http<{ resources: string[] }>(`${base(ctx)}/devices/queries/devices/v1?filter=${filter}`, { headers: await auth(ctx) });
    const ids = res.data.resources ?? [];
    if (!ids.length) return { ok: false, reason: `no host named ${target} in Falcon` };
    if (ids.length > 1) return { ok: false, reason: `${ids.length} Falcon hosts are named ${target}; contain the right one by hand` };
    const d = await device(ctx, ids[0]);
    if (!d) return { ok: false, reason: `Falcon listed ${target} but returned no details` };
    const contain = action === "ISOLATE_HOST";
    return { ok: true, resolved: { id: d.device_id, name: d.hostname, state: d.status }, alreadyDone: contain ? d.status === "contained" : d.status === "normal" };
  },

  async execute({ action, ctx }, resolved) {
    const name = action === "ISOLATE_HOST" ? "contain" : "lift_containment";
    await ctx.http(`${base(ctx)}/devices/entities/devices-actions/v2?action_name=${name}`, { headers: await auth(ctx), json: { ids: [resolved.id] } });
    return { ref: { deviceId: resolved.id, hostname: resolved.name }, confirmed: false, message: `${name === "contain" ? "Containment" : "Lifting containment"} requested in Falcon` };
  },

  async verify({ action, ctx }, ref) {
    const d = await device(ctx, ref.deviceId);
    if (!d) return { state: "failed", message: `Falcon no longer lists ${ref.hostname}` };
    const want = action === "ISOLATE_HOST" ? "contained" : "normal";
    if (d.status === want) return { state: "confirmed", message: `Falcon shows ${ref.hostname} ${want}` };
    if (d.status.endsWith("_pending")) return { state: "pending", message: `Falcon shows ${ref.hostname} ${d.status.replace(/_/g, " ")}` };
    return { state: "failed", message: `Falcon shows ${ref.hostname} ${d.status}` };
  },
};
