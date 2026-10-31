import { createHash } from "node:crypto";
import type { CaseSeverity, OrgPolicy, PlaybookActionType, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { endpointClass } from "@/lib/assets/inventory";
import { canonicalJson, isRuledAction, rulebookSchema, type Rulebook } from "@/lib/rulebook/schema";
import { humanGate, rulebookHits, type AllowlistFact, type AssetFacts, type RuleHit } from "@/lib/rulebook/evaluate";
import { approveChange, requestChange, withdrawRulebookChange, type ChangeActor } from "@/lib/changes/service";

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
  // The stored text no longer matches the hash that was approved: someone
  // changed it outside HELIOS. Nothing runs automatically under it.
  tampered?: boolean;
}

export function hashRulebook(body: Rulebook | unknown) {
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
  const tampered = !!row && hashRulebook(row.body) !== row.contentHash;
  const value = row ? { id: row.id, version: row.version, hash: row.contentHash, body: parseStored(row), signedByName: row.signedByName, signedAt: row.signedAt, tampered } : null;
  cache.set(tenantId, { at: Date.now(), value });
  if (tampered) await reportTampering(tenantId, row!.version);
  return value;
}

// Once an hour at most per client: the SOC's managers and the audit chain hear of it.
const tamperReported = new Map<string, number>();
async function reportTampering(tenantId: string, version: number) {
  const last = tamperReported.get(tenantId) ?? 0;
  if (Date.now() - last < 3_600_000) return;
  tamperReported.set(tenantId, Date.now());
  await logAction({ action: "rulebook.integrity_failed", detail: { tenantId, version } });
  const { notify, staffFor } = await import("@/lib/notifications");
  await notify(await staffFor(["ADMIN", "SOC_MANAGER"]), { kind: "rulebook", title: "A client's rulebook doesn't match what was approved", body: `Version ${version} was changed outside HELIOS. AI containment for this client now needs a person until a version is approved again.`, href: "/rulebook" });
}

// The hit a tampered rulebook puts on every decision.
export const TAMPERED_HIT: RuleHit = { rule: "rulebook.integrity", outcome: "PENDING_APPROVAL", reason: "The rulebook in force doesn't match the text that was approved; a person decides", hard: false };

// ---------------------------------------------------------------- decisions

const ALLOWLIST_KIND: Partial<Record<PlaybookActionType, string>> = {
  ISOLATE_HOST: "host",
  COLLECT_LOGS: "host",
  COLLECT_FORENSICS: "host",
  BLOCK_IP: "ip",
  DISABLE_USER: "user",
  RESET_PASSWORD: "user",
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
  if (rb?.tampered) return { version: rb.version, hash: rb.hash, hits: [TAMPERED_HIT] };
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
  // An edit after submission is a new text: the approvals asked for lapse.
  await withdrawRulebookChange(tenantId, saved.id, author, "The draft was edited after it was submitted");
  await logAction({ actorId: author.id, action: "rulebook.draft_saved", detail: { tenantId, version: saved.version, hash: contentHash, reason } });
  return saved;
}

export async function discardDraft(tenantId: string, author: Author) {
  const open = await db.orgPolicy.findFirst({ where: { tenantId, status: { in: ["DRAFT", "AWAITING_SIGNATURE"] } } });
  if (!open) return;
  await withdrawRulebookChange(tenantId, open.id, author, "The draft was discarded");
  await db.orgPolicy.delete({ where: { id: open.id } });
  await logAction({ actorId: author.id, action: "rulebook.draft_discarded", detail: { tenantId, version: open.version } });
}

// A draft goes for approval. It takes effect only once the client has
// signed it and HELIOS has approved it (lib/changes): until then the version
// in force keeps deciding.
export async function submitForSignature(tenantId: string, author: ChangeActor) {
  const draft = await db.orgPolicy.findFirst({ where: { tenantId, status: "DRAFT" } });
  if (!draft) throw new Error("There's no draft to send");
  if (hashRulebook(draft.body) !== draft.contentHash) throw new Error("This draft changed since it was saved; save it again");
  await db.orgPolicy.update({ where: { id: draft.id }, data: { status: "AWAITING_SIGNATURE", submittedAt: new Date() } });
  const change = await requestChange(
    { tenantId, kind: "RULEBOOK_VERSION", summary: `Rulebook v${draft.version}${draft.reason ? `: ${draft.reason}` : ""}`, reason: draft.reason ?? "New rulebook version", payload: { policyId: draft.id, version: draft.version, contentHash: draft.contentHash } },
    author,
  );
  await logAction({ actorId: author.id, action: "rulebook.submitted", detail: { tenantId, version: draft.version, hash: draft.contentHash, changeId: change.id } });
  const admins = await db.user.count({ where: { tenantId, role: "CLIENT_ADMIN", active: true } });
  return { notified: admins, changeId: change.id };
}

// One of the two approvals a submitted version needs: the client's (its
// admin signs, or HELIOS staff record the client's instruction) or HELIOS's
// (an approver other than whoever submitted it). The second one puts the
// version in force.
export async function signRulebook(tenantId: string, signer: ChangeActor, note: string, side: "client" | "helios" = "client") {
  const change = await db.ruleChange.findFirst({ where: { tenantId, kind: "RULEBOOK_VERSION", status: "PENDING" }, orderBy: { createdAt: "desc" } });
  if (!change) throw new Error("There's no version waiting to be signed");
  const result = await approveChange(change.id, side, signer, note);
  const version = (change.payload as { version: number }).version;
  return { version, active: result.applied };
}

export async function rulebookState(tenantId: string) {
  const versions = await db.orgPolicy.findMany({ where: { tenantId }, orderBy: { version: "desc" } });
  const active = versions.find((v) => v.status === "ACTIVE") ?? null;
  const draft = versions.find((v) => v.status === "DRAFT" || v.status === "AWAITING_SIGNATURE") ?? null;
  return { versions, active, draft };
}

// ---------------------------------------------------------------- allowlist

// Allowlist entries stop containment of what they name, so adding or
// removing one is a rule change: it takes effect once the client and HELIOS
// have approved it (lib/changes).
export async function addAllowlistEntry(tenantId: string, input: { kind: string; value: string; reason: string; owner: string; expiresAt: Date | null }, author: ChangeActor) {
  return requestChange(
    {
      tenantId,
      kind: "ALLOWLIST_ADD",
      summary: `Allow ${input.kind} ${input.value} (${input.reason}; owner ${input.owner}${input.expiresAt ? `; until ${input.expiresAt.toISOString().slice(0, 10)}` : ""})`,
      reason: input.reason,
      payload: { kind: input.kind, value: input.value, reason: input.reason, owner: input.owner, expiresAt: input.expiresAt?.toISOString() ?? null },
    },
    author,
  );
}

export async function removeAllowlistEntry(tenantId: string, entryId: string, author: ChangeActor, reason = "No longer needed") {
  const row = await db.policyAllowlistEntry.findFirst({ where: { id: entryId, tenantId } });
  if (!row) throw new Error("Not found");
  return requestChange({ tenantId, kind: "ALLOWLIST_REMOVE", summary: `Stop allowing ${row.kind} ${row.value}`, reason, payload: { entryId: row.id, kind: row.kind, value: row.value } }, author);
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
