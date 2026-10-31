"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { dump, load } from "js-yaml";

import { db } from "@/lib/db";
import { requirePermission, type SessionUser } from "@/lib/session";
import { notify } from "@/lib/notifications";
import { dispatchChatMessage } from "@/lib/integrations/chat";
import { sendAlert } from "@/lib/alerts/send";
import { logAction } from "@/lib/audit";
import { approverSchema, rulebookSchema } from "@/lib/rulebook/schema";
import { dryRunRulebook } from "@/lib/rulebook/dry-run";
import { addAllowlistEntry, discardDraft, removeAllowlistEntry, saveDraft, signRulebook, submitForSignature } from "@/lib/rulebook/service";
import { action } from "@/lib/action";
import { changeActorOf } from "@/lib/changes/rules";
import { removeGitSync, saveGitSync, syncRulebook, type GitSyncInput } from "@/lib/rulebook/git-sync";

// Client users work on their own rulebook only; staff on any client's.
async function actorFor(tenantId: string, permission: "rulebook.view" | "rulebook.edit" | "rulebook.sign"): Promise<SessionUser> {
  const user = await requirePermission(permission);
  if (user.isClient && user.tenantId !== tenantId) throw new Error("Not found");
  if (!(await db.tenant.count({ where: { id: tenantId } }))) throw new Error("Not found");
  return user;
}

const author = (u: SessionUser) => ({ id: u.id, name: u.name ?? u.email ?? "user" });

function done(tenantId: string) {
  revalidatePath("/rulebook");
  revalidatePath(`/tenants/${tenantId}`);
}

// Validation problems as one readable message: "schedule.timeZone: Unknown time zone".
function explain(err: unknown): never {
  if (err instanceof z.ZodError) throw new Error(err.issues.slice(0, 4).map((i) => `${i.path.join(".") || "rulebook"}: ${i.message}`).join("; "));
  throw err;
}

export const saveRulebookDraftAction = action(async function saveRulebookDraftAction(tenantId: string, input: { body: unknown; reason: string; template?: string | null }) {
  const user = await actorFor(tenantId, "rulebook.edit");
  try {
    const saved = await saveDraft(tenantId, { body: input.body, reason: String(input.reason ?? "").slice(0, 1000), template: input.template ?? null }, author(user));
    done(tenantId);
    return { version: saved.version };
  } catch (err) {
    explain(err);
  }
});

export const discardRulebookDraftAction = action(async function discardRulebookDraftAction(tenantId: string) {
  const user = await actorFor(tenantId, "rulebook.edit");
  await discardDraft(tenantId, author(user));
  done(tenantId);
});

export const submitRulebookAction = action(async function submitRulebookAction(tenantId: string) {
  const user = await actorFor(tenantId, "rulebook.edit");
  const result = await submitForSignature(tenantId, changeActorOf(user));
  done(tenantId);
  return result;
});

// One of the two approvals a submitted version needs: the client's (its
// admin, or staff recording the client's instruction) or HELIOS's.
export const signRulebookAction = action(async function signRulebookAction(tenantId: string, input: { note: string; acknowledged: boolean; side?: "client" | "helios" }) {
  const user = await actorFor(tenantId, "rulebook.sign");
  if (!input.acknowledged) throw new Error("Confirm you've read the rulebook and authorise HELIOS to act under it");
  const side = user.isClient ? "client" : input.side === "helios" ? "helios" : "client";
  const result = await signRulebook(tenantId, changeActorOf(user), String(input.note ?? "").slice(0, 1000), side);
  done(tenantId);
  revalidatePath("/changes");
  return result;
});

export const dryRunRulebookAction = action(async function dryRunRulebookAction(tenantId: string, body: unknown) {
  await actorFor(tenantId, "rulebook.view");
  try {
    return await dryRunRulebook(tenantId, rulebookSchema.parse(body));
  } catch (err) {
    explain(err);
  }
});

// Policy as code: the same schema, written as YAML.
export const exportRulebookYamlAction = action(async function exportRulebookYamlAction(tenantId: string, body: unknown) {
  await actorFor(tenantId, "rulebook.view");
  return dump(rulebookSchema.parse(body), { lineWidth: 120, noRefs: true, sortKeys: false });
});

export const importRulebookYamlAction = action(async function importRulebookYamlAction(tenantId: string, input: { yaml: string; reason: string }) {
  const user = await actorFor(tenantId, "rulebook.edit");
  if (input.yaml.length > 200_000) throw new Error("That file is too large for a rulebook");
  let parsed: unknown;
  try {
    // js-yaml 4's load is safe: plain data only, no custom types.
    parsed = load(input.yaml);
  } catch (err) {
    throw new Error(`Not valid YAML: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`);
  }
  try {
    const saved = await saveDraft(tenantId, { body: parsed, reason: String(input.reason ?? "").slice(0, 1000), template: "yaml" }, author(user));
    done(tenantId);
    return { version: saved.version };
  } catch (err) {
    explain(err);
  }
});

const allowlistInput = z.object({
  kind: z.enum(["ip", "host", "user", "domain", "hash", "process", "sender"]),
  value: z.string().trim().min(1).max(300),
  reason: z.string().trim().min(3, "Say why it's allowed").max(500),
  owner: z.string().trim().min(2, "Name an owner").max(120),
  expiresAt: z.string().trim().max(40).optional().nullable(),
});

export const addAllowlistEntryAction = action(async function addAllowlistEntryAction(tenantId: string, input: z.input<typeof allowlistInput>) {
  const user = await actorFor(tenantId, "rulebook.edit");
  const data = allowlistInput.parse(input);
  const expiresAt = data.expiresAt ? new Date(data.expiresAt) : null;
  if (expiresAt && (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date())) throw new Error("Expiry must be a future date");
  await addAllowlistEntry(tenantId, { kind: data.kind, value: data.value, reason: data.reason, owner: data.owner, expiresAt }, changeActorOf(user));
  done(tenantId);
  revalidatePath("/changes");
});

export const removeAllowlistEntryAction = action(async function removeAllowlistEntryAction(tenantId: string, entryId: string, reason?: string) {
  const user = await actorFor(tenantId, "rulebook.edit");
  await removeAllowlistEntry(tenantId, entryId, changeActorOf(user), String(reason ?? "").trim().slice(0, 500) || "No longer needed");
  done(tenantId);
  revalidatePath("/changes");
});

// A live ping to one approver, so a dead channel shows up before it matters.
export const testApproverAction = action(async function testApproverAction(tenantId: string, input: unknown) {
  const user = await actorFor(tenantId, "rulebook.edit");
  const approver = approverSchema.parse(input);
  const tenant = await db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { name: true } });
  const text = `HELIOS test: ${approver.name} is an approver for ${tenant.name}. No action needed.`;
  if (approver.channel === "app") {
    const users = await db.user.findMany({ where: { email: { equals: approver.contact, mode: "insensitive" }, active: true }, select: { id: true } });
    if (!users.length) return { ok: false, message: `No active HELIOS user with the email ${approver.contact}` };
    await notify(users.map((u) => u.id), { kind: "rulebook", title: "Approver test", body: text, actorName: user.name ?? null });
    return { ok: true, message: `Sent to ${approver.name} in HELIOS` };
  }
  if (approver.channel === "slack" || approver.channel === "teams") {
    const sent = await dispatchChatMessage(tenantId, text);
    return { ok: sent.sent, message: sent.message };
  }
  if (approver.channel === "email" || approver.channel === "sms" || approver.channel === "whatsapp") {
    const r = await sendAlert(approver.channel, approver.contact.trim(), { subject: "Approver test", body: text });
    await logAction({ actorId: user.id, action: "rulebook.approver_tested", detail: { tenantId, channel: approver.channel, ok: r.ok, error: r.error ?? null } });
    return { ok: r.ok, message: r.ok ? `Sent to ${approver.name} by ${approver.channel === "email" ? "email" : approver.channel === "sms" ? "SMS" : "WhatsApp"}` : r.error ?? "Not sent" };
  }
  return { ok: false, message: `HELIOS doesn't place calls itself: the SOC is asked to ring ${approver.name} on ${approver.contact} when an approval is due. Check the number by hand.` };
});

// Git sync: keep the rulebook as YAML in the client's repository.
export const saveGitSyncAction = action(async function saveGitSyncAction(tenantId: string, input: GitSyncInput) {
  const user = await actorFor(tenantId, "rulebook.edit");
  try {
    await saveGitSync(tenantId, input, user.id);
  } catch (err) {
    explain(err);
  }
  done(tenantId);
});

export const removeGitSyncAction = action(async function removeGitSyncAction(tenantId: string) {
  const user = await actorFor(tenantId, "rulebook.edit");
  await removeGitSync(tenantId, user.id);
  done(tenantId);
});

export const syncRulebookNowAction = action(async function syncRulebookNowAction(tenantId: string) {
  const user = await actorFor(tenantId, "rulebook.edit");
  const r = await syncRulebook(tenantId, { actor: author(user) });
  done(tenantId);
  return r;
});
