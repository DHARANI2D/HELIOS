import { microsoftToken, odata } from "@/lib/connectors/http";
import type { ConnectorCtx, NativeConnector, Preflight } from "@/lib/connectors/types";

// Microsoft Entra ID through Microsoft Graph: disable an account and revoke
// its sign-in sessions, or re-enable it. Confirmed by reading accountEnabled
// back. Application permissions: User.EnableDisableAccount.All, User.Read.All
// and User.RevokeSessions.All (or User.ReadWrite.All).

const GRAPH = "https://graph.microsoft.com/v1.0";
const SCOPE = "https://graph.microsoft.com/.default";

interface GraphUser {
  id: string;
  userPrincipalName: string;
  accountEnabled: boolean;
}

async function auth(ctx: ConnectorCtx) {
  return { authorization: `Bearer ${await microsoftToken(ctx, SCOPE)}` };
}

const SELECT = "$select=id,userPrincipalName,accountEnabled";

// "jdoe@corp.example" directly; "CORP\\jdoe" or "jdoe" by on-premises
// account name or mail nickname.
async function findUser(ctx: ConnectorCtx, target: string): Promise<GraphUser | null | "ambiguous"> {
  const headers = await auth(ctx);
  if (target.includes("@")) {
    const res = await ctx.http<GraphUser>(`${GRAPH}/users/${encodeURIComponent(target)}?${SELECT}`, { headers, expect: [404] });
    return res.status === 404 ? null : res.data;
  }
  const name = odata(target.includes("\\") ? target.split("\\").pop()! : target);
  const filter = encodeURIComponent(`onPremisesSamAccountName eq '${name}' or mailNickname eq '${name}'`);
  const res = await ctx.http<{ value: GraphUser[] }>(`${GRAPH}/users?$filter=${filter}&${SELECT}&$count=true`, { headers: { ...headers, ConsistencyLevel: "eventual" } });
  if (res.data.value.length > 1) return "ambiguous";
  return res.data.value[0] ?? null;
}

export const entra: NativeConnector = {
  key: "entra_id",
  label: "Microsoft Entra ID",
  tools: ["entra_p1", "entra_p2"],
  actions: ["DISABLE_USER", "ENABLE_USER"],
  docs: "https://learn.microsoft.com/graph/api/user-update · /user-revokesigninsessions",
  fields: [
    { key: "tenantId", label: "Directory (tenant) ID", required: true },
    { key: "clientId", label: "Application (client) ID", required: true },
    { key: "clientSecret", label: "Client secret", secret: true, required: true },
  ],

  async check(ctx) {
    await ctx.http(`${GRAPH}/users?$top=1&$select=id`, { headers: await auth(ctx) });
    return { ok: true, message: "Signed in to Microsoft Graph and read the user list" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    const user = await findUser(ctx, target);
    if (user === "ambiguous") return { ok: false, reason: `more than one Entra ID account matches ${target}; use the full sign-in name` };
    if (!user) return { ok: false, reason: `no Entra ID account ${target}` };
    const disable = action === "DISABLE_USER";
    return { ok: true, resolved: { id: user.id, name: user.userPrincipalName, state: user.accountEnabled ? "enabled" : "disabled" }, alreadyDone: disable ? !user.accountEnabled : user.accountEnabled };
  },

  async execute({ action, ctx }, resolved) {
    const headers = await auth(ctx);
    const disable = action === "DISABLE_USER";
    await ctx.http(`${GRAPH}/users/${encodeURIComponent(resolved.id)}`, { method: "PATCH", headers, json: { accountEnabled: !disable } });
    // Disabling stops new sign-ins; revoking ends the sessions already open.
    if (disable) await ctx.http(`${GRAPH}/users/${encodeURIComponent(resolved.id)}/revokeSignInSessions`, { method: "POST", headers });
    return { ref: { userId: resolved.id, upn: resolved.name }, confirmed: false, message: disable ? `Disabled ${resolved.name} and revoked its sessions in Entra ID` : `Re-enabled ${resolved.name} in Entra ID` };
  },

  async verify({ action, ctx }, ref) {
    const res = await ctx.http<GraphUser>(`${GRAPH}/users/${encodeURIComponent(ref.userId)}?${SELECT}`, { headers: await auth(ctx) });
    const want = action !== "DISABLE_USER";
    return res.data.accountEnabled === want
      ? { state: "confirmed", message: `Entra ID shows ${ref.upn} ${want ? "enabled" : "disabled"}` }
      : { state: "pending", message: `Entra ID still shows ${ref.upn} ${want ? "disabled" : "enabled"}` };
  },
};
