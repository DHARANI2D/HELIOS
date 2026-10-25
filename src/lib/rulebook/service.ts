import { createHash } from "node:crypto";
import type { CaseSeverity, OrgPolicy, PlaybookActionType, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify } from "@/lib/notifications";
import { endpointClass } from "@/lib/assets/inventory";
import { canonicalJson, isRuledAction, rulebookSchema, type Rulebook } from "@/lib/rulebook/schema";
import { humanGate, rulebookHits, type AllowlistFact, type AssetFacts, type RuleHit } from "@/lib/rulebook/evaluate";

// Client rulebooks on the server: the active version (cached briefly, since
// the response policy reads it on every decision), drafts, signing, the
// allowlist, and the facts a decision needs (the target asset, allowlist
// matches, counters). Each activated version goes into the audit chain with
// its hash, and the hash is stored on every decision it produced.

export interface ActiveRulebook {
  id: string;
  version: number;
  hash: string;
  body: Rulebook;
  signedByName: string | null;
  signedAt: Date | null;
}

export function hashRulebook(body: Rulebook) {
  return createHash("sha256").update(canonicalJson(body)).digest("hex");
}

const TTL_MS = 30_000;
const cache = new Map<string, { at: number; value: ActiveRulebook | null }>();

export function forgetRulebook(tenantId: string) {
  cache.delete(tenantId);
}

export function parseStored(row: Pick<OrgPolicy, "body">): Rulebook {
  // Stored bodies were validated when saved; re-parsing fills defaults added
  // to the schema since.
  return rulebookSchema.parse(row.body);
}

export async function activeRulebook(tenantId: string | null | undefined, fresh = false): Promise<ActiveRulebook | null> {
  if (!tenantId) return null;
  const hit = cache.get(tenantId);
  if (!fresh && hit && Date.now() - hit.at < TTL_MS) return hit.value;
  const row = await db.orgPolicy.findFirst({ where: { tenantId, status: "ACTIVE" }, orderBy: { version: "desc" } });
  const value = row ? { id: row.id, version: row.version, hash: row.contentHash, body: parseStored(row), signedByName: row.signedByName, signedAt: row.signedAt } : null;
  cache.set(tenantId, { at: Date.now(), value });
  return value;
}

// ---------------------------------------------------------------- decisions

const ALLOWLIST_KIND: Partial<Record<PlaybookActionType, string>> = {
  ISOLATE_HOST: "host",
  COLLECT_LOGS: "host",
  BLOCK_IP: "ip",
  DISABLE_USER: "user",
  BLOCK_SENDER: "sender",
  QUARANTINE_FILE: "hash",
  KILL_PROCESS: "process",
};

export async function allowlistMatch(tenantId: string, actionType: PlaybookActionType, target: string | null, now = new Date()): Promise<AllowlistFact | null> {
  const kind = ALLOWLIST_KIND[actionType];
  if (!kind || !target) return null;
  const values = [target];
  // A sender is vouched for by address or by its whole domain.
  if (kind === "sender" && target.includes("@")) values.push(target.split("@").pop()!);
  const rows = await db.policyAllowlistEntry.findMany({
    where: { tenantId, kind: kind === "sender" ? { in: ["sender", "domain"] } : kind, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
  });
  const row = rows.find((r) => values.some((v) => v.toLowerCase() === r.value.toLowerCase()));
  return row ? { kind: row.kind, value: row.value, reason: row.reason, owner: row.owner, expiresAt: row.expiresAt } : null;
}

async function assetFor(tenantId: string, actionType: PlaybookActionType, target: string | null): Promise<AssetFacts | null> {
  if (!target) return null;
  const select = { hostname: true, ipAddress: true, assetClass: true, assetType: true, criticality: true, os: true } as const;
  const row =
    actionType === "BLOCK_IP"
      ? await db.endpoint.findFirst({ where: { tenantId, ipAddress: target }, select })
      : actionType === "ISOLATE_HOST" || actionType === "COLLECT_LOGS" || actionType === "RELEASE_HOST"
        ? await db.endpoint.findFirst({ where: { tenantId, hostname: { equals: target, mode: "insensitive" } }, select })
        : null;
  if (!row) return actionType === "BLOCK_IP" ? { ip: target } : actionType === "ISOLATE_HOST" || actionType === "COLLECT_LOGS" ? { hostname: target } : null;
  return { hostname: row.hostname, ip: row.ipAddress, assetGroup: endpointClass(row), assetType: row.assetType, criticality: row.criticality };
}

export interface RulebookVerdict {
  version: number;
  hash: string;
  hits: RuleHit[];
}

// What the client's active rulebook says about one action, or null when the
// client has none (the plan, consent and agent profile still apply).
export async function rulebookVerdict(input: {
  tenantId: string | null | undefined;
  actionType: PlaybookActionType;
  target: string | null;
  severity: CaseSeverity;
  now?: Date;
  fresh?: boolean;
}): Promise<RulebookVerdict | null> {
  const rb = await activeRulebook(input.tenantId, input.fresh);
  if (!rb || !input.tenantId || !isRuledAction(input.actionType)) return rb && { version: rb.version, hash: rb.hash, hits: [] };
  const now = input.now ?? new Date();
  const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  const [asset, allowlisted, aiActionsLastHour, hostsIsolated] = await Promise.all([
    assetFor(input.tenantId, input.actionType, input.target),
    allowlistMatch(input.tenantId, input.actionType, input.target, now),
    db.responseAction.count({ where: { tenantId: input.tenantId, source: "ai", status: "EXECUTED", createdAt: { gte: hourAgo } } }),
    db.endpoint.count({ where: { tenantId: input.tenantId, isolated: true } }),
  ]);
  const hits = rulebookHits(rb.body, { actionType: input.actionType, target: input.target, severity: input.severity, now, asset, allowlisted, aiActionsLastHour, hostsIsolated });
  return { version: rb.version, hash: rb.hash, hits };
}

// For a person asking for an action: only the hard rules bind (a
// never-isolate asset, a protected account, an action the client forbids,
// the two-person rule).
export async function humanRulebookGate(input: { tenantId: string | null | undefined; actionType: PlaybookActionType; target: string | null; severity: CaseSeverity; fresh?: boolean }) {
  const verdict = await rulebookVerdict(input);
  if (!verdict) return { allowed: true, reason: null, approvals: 1, version: null, hash: null };
  return { ...humanGate(verdict.hits), version: verdict.version, hash: verdict.hash };
}

// ---------------------------------------------------------------- versions

export interface Author {
  id: string;
  name: string;
}

async function nextVersion(tx: Prisma.TransactionClient, tenantId: string) {
  const last = await tx.orgPolicy.findFirst({ where: { tenantId }, orderBy: { version: "desc" }, select: { version: true } });
  return (last?.version ?? 0) + 1;
}

// One open draft per client: saving updates it, or starts the next version.
export async function saveDraft(tenantId: string, input: { body: unknown; reason: string; template?: string | null }, author: Author) {
  const body = rulebookSchema.parse(input.body);
  const reason = input.reason.trim();
  if (reason.length < 3) throw new Error("Say why this version changes the rules");
  const contentHash = hashRulebook(body);
  const saved = await db.$transaction(async (tx) => {
    const open = await tx.orgPolicy.findFirst({ where: { tenantId, status: { in: ["DRAFT", "AWAITING_SIGNATURE"] } } });
    const data = { body: JSON.parse(JSON.stringify(body)), contentHash, reason, template: input.template ?? open?.template ?? null, authoredById: author.id, authoredByName: author.name, status: "DRAFT" as const, submittedAt: null };
    if (open) return tx.orgPolicy.update({ where: { id: open.id }, data });
    return tx.orgPolicy.create({ data: { ...data, tenantId, version: await nextVersion(tx, tenantId) } });
  });
  await logAction({ actorId: author.id, action: "rulebook.draft_saved", detail: { tenantId, version: saved.version, hash: contentHash, reason } });
  return saved;
}

export async function discardDraft(tenantId: string, author: Author) {
  const open = await db.orgPolicy.findFirst({ where: { tenantId, status: { in: ["DRAFT", "AWAITING_SIGNATURE"] } } });
  if (!open) return;
  await db.orgPolicy.delete({ where: { id: open.id } });
  await logAction({ actorId: author.id, action: "rulebook.draft_discarded", detail: { tenantId, version: open.version } });
}

export async function submitForSignature(tenantId: string, author: Author) {
  const draft = await db.orgPolicy.findFirst({ where: { tenantId, status: "DRAFT" } });
  if (!draft) throw new Error("There's no draft to send");
  await db.orgPolicy.update({ where: { id: draft.id }, data: { status: "AWAITING_SIGNATURE", submittedAt: new Date() } });
  const admins = await db.user.findMany({ where: { tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
  await notify(admins.map((a) => a.id), {
    kind: "approval",
    title: `Rulebook v${draft.version} is ready to sign`,
    body: draft.reason ?? "Review what HELIOS may do on your estate, then sign it to put it in force.",
    actorName: author.name,
    href: "/rulebook",
  });
  await logAction({ actorId: author.id, action: "rulebook.submitted", detail: { tenantId, version: draft.version, hash: draft.contentHash, notified: admins.length } });
  return { notified: admins.length };
}

// The client admin signs and the version takes effect. Staff can activate
// on the client's behalf only with a note recording the client's instruction.
export async function signRulebook(tenantId: string, signer: Author & { isClient: boolean }, note: string) {
  const text = note.trim();
  if (!signer.isClient && text.length < 10) throw new Error("Record the client's instruction (who approved it, when and how)");
  const pending = await db.orgPolicy.findFirst({ where: { tenantId, status: { in: signer.isClient ? ["AWAITING_SIGNATURE"] : ["AWAITING_SIGNATURE", "DRAFT"] } } });
  if (!pending) throw new Error("There's no version waiting to be signed");
  // The stored body must still match its hash: what was reviewed is what runs.
  const body = parseStored(pending);
  if (hashRulebook(body) !== pending.contentHash) throw new Error("This version changed since it was saved; save it again");
  const now = new Date();
  const activated = await db.$transaction(async (tx) => {
    await tx.orgPolicy.updateMany({ where: { tenantId, status: "ACTIVE" }, data: { status: "SUPERSEDED" } });
    return tx.orgPolicy.update({
      where: { id: pending.id },
      data: {
        status: "ACTIVE",
        signedById: signer.id,
        signedByName: signer.name,
        signedAt: now,
        effectiveFrom: now,
        signatureNote: signer.isClient ? text || null : `Activated by ${signer.name} on the client's instruction: ${text}`,
      },
    });
  });
  forgetRulebook(tenantId);
  await logAction({ actorId: signer.id, action: "rulebook.activated", detail: { tenantId, version: activated.version, hash: activated.contentHash, onBehalf: !signer.isClient, note: text || null } });
  return activated;
}

export async function rulebookState(tenantId: string) {
  const versions = await db.orgPolicy.findMany({ where: { tenantId }, orderBy: { version: "desc" } });
  const active = versions.find((v) => v.status === "ACTIVE") ?? null;
  const draft = versions.find((v) => v.status === "DRAFT" || v.status === "AWAITING_SIGNATURE") ?? null;
  return { versions, active, draft };
}

// ---------------------------------------------------------------- allowlist

export async function addAllowlistEntry(tenantId: string, input: { kind: string; value: string; reason: string; owner: string; expiresAt: Date | null }, author: Author) {
  const row = await db.policyAllowlistEntry.create({ data: { tenantId, ...input, createdById: author.id } });
  await logAction({ actorId: author.id, action: "rulebook.allowlist_added", detail: { tenantId, entryId: row.id, kind: row.kind, value: row.value, reason: row.reason, owner: row.owner, expiresAt: row.expiresAt?.toISOString() ?? null } });
  return row;
}

export async function removeAllowlistEntry(tenantId: string, entryId: string, author: Author) {
  const row = await db.policyAllowlistEntry.findFirst({ where: { id: entryId, tenantId } });
  if (!row) throw new Error("Not found");
  await db.policyAllowlistEntry.delete({ where: { id: row.id } });
  await logAction({ actorId: author.id, action: "rulebook.allowlist_removed", detail: { tenantId, entryId, kind: row.kind, value: row.value } });
}

// What needs a look: a rulebook past its review date, allowlist entries
// about to lapse.
export async function rulebookReminders(tenantId: string, now = new Date()) {
  const [active, expiring] = await Promise.all([
    activeRulebook(tenantId),
    db.policyAllowlistEntry.findMany({ where: { tenantId, expiresAt: { gt: now, lte: new Date(now.getTime() + 14 * 86_400_000) } }, orderBy: { expiresAt: "asc" } }),
  ]);
  const reviewDue = active?.signedAt ? new Date(active.signedAt.getTime() + active.body.reviewEveryDays * 86_400_000) : null;
  return { reviewDue, reviewOverdue: !!reviewDue && reviewDue <= now, expiring };
}
