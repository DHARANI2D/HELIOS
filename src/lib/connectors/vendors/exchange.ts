import { microsoftToken, odata } from "@/lib/connectors/http";
import type { ConnectorCtx, NativeConnector, Preflight } from "@/lib/connectors/types";
import { parsePurgeTarget } from "@/lib/response/targets";

// Microsoft Exchange Online through Microsoft Graph's mail API: remove a
// delivered message from its recipients' mailboxes. Each copy is found by
// its Internet Message-ID and moved to Recoverable Items (the well-known
// folder recoverableitemsdeletions): out of the user's sight, restorable by
// an admin. Confirmed when no recipient's mailbox lists it any more (the
// message list covers every folder but Recoverable Items).
//
// Application permission: Mail.ReadWrite. That reaches every mailbox, so
// limit it with RBAC for Applications in Exchange Online to the mailboxes
// HELIOS may touch.
//
// Blocking a sender for the whole tenant is the Tenant Allow/Block List,
// which Microsoft Graph doesn't expose (it's Exchange Online PowerShell,
// New-TenantAllowBlockListItems); that stays with a mail gateway connector,
// the client's own automation through the signed webhook, or a person.

const GRAPH = "https://graph.microsoft.com/v1.0";
const SCOPE = "https://graph.microsoft.com/.default";

async function auth(ctx: ConnectorCtx) {
  return { authorization: `Bearer ${await microsoftToken(ctx, SCOPE)}` };
}

interface Copy {
  mailbox: string;
  id: string;
}

// The copies of a message in each mailbox; a mailbox that doesn't exist is
// noted, not fatal.
async function copies(ctx: ConnectorCtx, messageId: string, mailboxes: string[]) {
  const headers = await auth(ctx);
  const found: Copy[] = [];
  const missing: string[] = [];
  const filter = encodeURIComponent(`internetMessageId eq '${odata(messageId)}'`);
  for (const mailbox of mailboxes) {
    const res = await ctx.http<{ value: Array<{ id: string }> }>(`${GRAPH}/users/${encodeURIComponent(mailbox)}/messages?$filter=${filter}&$select=id&$top=25`, { headers, expect: [404] });
    if (res.status === 404) missing.push(mailbox);
    else for (const m of res.data.value ?? []) found.push({ mailbox, id: m.id });
  }
  return { found, missing };
}

export const exchange: NativeConnector = {
  key: "exchange_online",
  label: "Microsoft Exchange Online",
  tools: ["defender_o365_p1", "defender_o365_p2"],
  actions: ["PURGE_EMAIL"],
  docs: "https://learn.microsoft.com/graph/api/user-list-messages · /message-move (destinationId recoverableitemsdeletions) · /resources/mailfolder",
  fields: [
    { key: "tenantId", label: "Directory (tenant) ID", required: true },
    { key: "clientId", label: "Application (client) ID", required: true },
    { key: "clientSecret", label: "Client secret", secret: true, required: true },
    { key: "testMailbox", label: "A mailbox to test with", placeholder: "soc-test@client.example", hint: "One mailbox the app may read, used only by the connection test" },
  ],

  async check(ctx) {
    const headers = await auth(ctx);
    if (!ctx.config.testMailbox) return { ok: true, message: "Signed in to Microsoft Graph; set a test mailbox to check mail access too" };
    await ctx.http(`${GRAPH}/users/${encodeURIComponent(ctx.config.testMailbox)}/mailFolders/inbox?$select=id`, { headers });
    return { ok: true, message: `Signed in to Microsoft Graph and opened ${ctx.config.testMailbox}'s inbox` };
  },

  async preflight({ target, ctx }): Promise<Preflight> {
    const parsed = parsePurgeTarget(target);
    if (!parsed) return { ok: false, reason: `"${target.slice(0, 80)}" isn't "<message-id> to recipient@…"` };
    const { found, missing } = await copies(ctx, parsed.messageId, parsed.recipients);
    if (missing.length === parsed.recipients.length) return { ok: false, reason: `none of the recipients has a mailbox in Exchange Online (${missing.slice(0, 3).join(", ")})` };
    const where = `${found.length} cop${found.length === 1 ? "y" : "ies"} in ${new Set(found.map((f) => f.mailbox)).size} of ${parsed.recipients.length} mailboxes`;
    return { ok: true, resolved: { id: parsed.messageId, name: `${parsed.messageId} (${where})`, state: found.length ? "delivered" : "not in any mailbox" }, alreadyDone: found.length === 0 };
  },

  async execute({ target, ctx }) {
    const parsed = parsePurgeTarget(target)!;
    const headers = await auth(ctx);
    const { found } = await copies(ctx, parsed.messageId, parsed.recipients);
    for (const c of found) {
      await ctx.http(`${GRAPH}/users/${encodeURIComponent(c.mailbox)}/messages/${encodeURIComponent(c.id)}/move`, { method: "POST", headers, json: { destinationId: "recoverableitemsdeletions" } });
    }
    const boxes = new Set(found.map((f) => f.mailbox)).size;
    return { ref: { messageId: parsed.messageId, moved: String(found.length) }, confirmed: false, message: `Moved ${found.length} cop${found.length === 1 ? "y" : "ies"} from ${boxes} mailbox${boxes === 1 ? "" : "es"} to Recoverable Items in Exchange Online` };
  },

  async verify({ target, ctx }, ref) {
    const parsed = parsePurgeTarget(target);
    if (!parsed) return { state: "failed", message: "the target can't be read back" };
    const { found } = await copies(ctx, ref.messageId ?? parsed.messageId, parsed.recipients);
    return found.length
      ? { state: "pending", message: `Exchange Online still lists ${found.length} cop${found.length === 1 ? "y" : "ies"} (${[...new Set(found.map((f) => f.mailbox))].slice(0, 3).join(", ")})` }
      : { state: "confirmed", message: `No recipient's mailbox lists the message any more; an admin can restore it from Recoverable Items` };
  },
};
