import { isIP } from "node:net";

import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx, Execution, NativeConnector, Preflight } from "@/lib/connectors/types";

// Cloudflare: block an IP across every zone in the client's account with an
// IP Access rule, and remove it again. Confirmed by listing the rule. An API
// token with Account Firewall Access Rules: Edit.

const API = "https://api.cloudflare.com/client/v4";

function rulesUrl(ctx: ConnectorCtx) {
  if (!ctx.config.accountId) throw new ConnectorError("Set the Cloudflare account ID", null);
  return `${API}/accounts/${encodeURIComponent(ctx.config.accountId)}/firewall/access_rules/rules`;
}

function auth(ctx: ConnectorCtx) {
  if (!ctx.secrets.apiToken) throw new ConnectorError("Set the API token", null);
  return { authorization: `Bearer ${ctx.secrets.apiToken}` };
}

interface AccessRule {
  id: string;
  mode: string;
  configuration: { target: string; value: string };
}

interface Envelope<T> {
  success: boolean;
  errors?: Array<{ message: string }>;
  result: T;
}

async function blockRule(ctx: ConnectorCtx, ip: string): Promise<AccessRule | null> {
  const res = await ctx.http<Envelope<AccessRule[]>>(`${rulesUrl(ctx)}?mode=block&configuration.target=${isIP(ip) === 6 ? "ip6" : "ip"}&configuration.value=${encodeURIComponent(ip)}`, { headers: auth(ctx) });
  return res.data.result?.find((r) => r.mode === "block" && r.configuration.value === ip) ?? null;
}

export const cloudflare: NativeConnector = {
  key: "cloudflare",
  label: "Cloudflare",
  tools: ["cloudflare_zero_trust", "cloudflare_pro", "cloudflare_business"],
  actions: ["BLOCK_IP", "UNBLOCK_IP"],
  docs: "https://developers.cloudflare.com/api/resources/firewall/subresources/access_rules/",
  fields: [
    { key: "accountId", label: "Account ID", required: true },
    { key: "apiToken", label: "API token", secret: true, required: true, hint: "Account Firewall Access Rules: Edit" },
  ],

  async check(ctx) {
    await ctx.http(`${rulesUrl(ctx)}?per_page=1`, { headers: auth(ctx) });
    return { ok: true, message: "Signed in to Cloudflare and read the account's IP Access rules" };
  },

  async preflight({ action, target, ctx }): Promise<Preflight> {
    if (!isIP(target)) return { ok: false, reason: `${target} isn't an IP address` };
    const rule = await blockRule(ctx, target);
    if (action === "BLOCK_IP") return { ok: true, resolved: { id: rule?.id ?? target, name: target }, alreadyDone: !!rule };
    return { ok: true, resolved: { id: rule?.id ?? "", name: target }, alreadyDone: !rule };
  },

  async execute({ action, target, ctx, comment, idempotencyKey }, resolved): Promise<Execution> {
    if (action === "UNBLOCK_IP") {
      await ctx.http(`${rulesUrl(ctx)}/${encodeURIComponent(resolved.id)}`, { method: "DELETE", headers: auth(ctx), expect: [404] });
      return { ref: { ip: target }, confirmed: false, message: `Removed the Cloudflare block on ${target}` };
    }
    const res = await ctx.http<Envelope<AccessRule>>(rulesUrl(ctx), {
      headers: auth(ctx),
      json: { mode: "block", configuration: { target: isIP(target) === 6 ? "ip6" : "ip", value: target }, notes: `HELIOS ${idempotencyKey}: ${comment}`.slice(0, 500) },
    });
    if (!res.data.success) throw new ConnectorError(`Cloudflare refused the rule: ${res.data.errors?.map((e) => e.message).join("; ")}`, null);
    return { ref: { ip: target, ruleId: res.data.result.id }, confirmed: false, message: `Cloudflare IP Access rule ${res.data.result.id} blocks ${target}` };
  },

  async verify({ action, ctx }, ref) {
    const rule = await blockRule(ctx, ref.ip);
    if (action === "UNBLOCK_IP") return rule ? { state: "pending", message: `Cloudflare still blocks ${ref.ip}` } : { state: "confirmed", message: `No Cloudflare block left on ${ref.ip}` };
    return rule ? { state: "confirmed", message: `Cloudflare blocks ${ref.ip} (rule ${rule.id})` } : { state: "failed", message: `Cloudflare shows no block on ${ref.ip}` };
  },
};
