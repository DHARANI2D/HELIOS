import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx, NativeConnector, Preflight } from "@/lib/connectors/types";

// Okta: suspend an account (which keeps its profile, factors and
// assignments, and ends its Okta session) and clear its sessions, or
// unsuspend it. Confirmed by reading the user's status back. An API token
// for an admin role that can manage users.

const base = (ctx: ConnectorCtx) => {
  const url = ctx.config.orgUrl?.replace(/\/+$/, "");
  if (!url) throw new ConnectorError("Set the Okta org URL", null);
  return `${url}/api/v1`;
};

function auth(ctx: ConnectorCtx) {
  if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
  return { authorization: `SSWS ${ctx.secrets.apiToken}` };
}

interface OktaUser {
  id: string;
  status: string; // ACTIVE | SUSPENDED | DEPROVISIONED | LOCKED_OUT | PASSWORD_EXPIRED | …
  profile: { login: string };
}

const login = (target: string) => (target.includes("\\") ? target.split("\\").pop()! : target);

export const okta: NativeConnector = {
  key: "okta",
  label: "Okta",
  tools: ["okta_workforce"],
  actions: ["DISABLE_USER", "ENABLE_USER"],
  docs: "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle (suspend, unsuspend) · User Sessions",
  fields: [
    { key: "orgUrl", label: "Okta org URL", required: true, placeholder: "https://acme.okta.com" },
    { key: "apiToken", label: "API token", secret: true, required: true },
  ],

  async check(ctx) {
    await ctx.http(`${base(ctx)}/users?limit=1`, { headers: auth(ctx) });
    return { ok: true, message: "Signed in to Okta and read the user list" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    const res = await ctx.http<OktaUser>(`${base(ctx)}/users/${encodeURIComponent(login(target))}`, { headers: auth(ctx), expect: [404] });
    if (res.status === 404) return { ok: false, reason: `no Okta user ${target}` };
    const u = res.data;
    const suspend = action === "DISABLE_USER";
    if (suspend && u.status === "SUSPENDED") return { ok: true, resolved: { id: u.id, name: u.profile.login, state: u.status }, alreadyDone: true };
    if (!suspend && u.status !== "SUSPENDED") return { ok: true, resolved: { id: u.id, name: u.profile.login, state: u.status }, alreadyDone: u.status === "ACTIVE" };
    if (suspend && u.status !== "ACTIVE") return { ok: false, reason: `${u.profile.login} is ${u.status.toLowerCase().replace(/_/g, " ")} in Okta; only active users can be suspended` };
    return { ok: true, resolved: { id: u.id, name: u.profile.login, state: u.status } };
  },

  async execute({ action, ctx }, resolved) {
    const suspend = action === "DISABLE_USER";
    await ctx.http(`${base(ctx)}/users/${encodeURIComponent(resolved.id)}/lifecycle/${suspend ? "suspend" : "unsuspend"}`, { method: "POST", headers: auth(ctx) });
    if (suspend) await ctx.http(`${base(ctx)}/users/${encodeURIComponent(resolved.id)}/sessions`, { method: "DELETE", headers: auth(ctx), expect: [404] });
    return { ref: { userId: resolved.id, login: resolved.name }, confirmed: false, message: suspend ? `Suspended ${resolved.name} in Okta and cleared its sessions` : `Unsuspended ${resolved.name} in Okta` };
  },

  async verify({ action, ctx }, ref) {
    const res = await ctx.http<OktaUser>(`${base(ctx)}/users/${encodeURIComponent(ref.userId)}`, { headers: auth(ctx) });
    const want = action === "DISABLE_USER" ? "SUSPENDED" : "ACTIVE";
    return res.data.status === want
      ? { state: "confirmed", message: `Okta shows ${ref.login} ${want.toLowerCase()}` }
      : { state: "pending", message: `Okta shows ${ref.login} ${res.data.status.toLowerCase()}` };
  },
};
