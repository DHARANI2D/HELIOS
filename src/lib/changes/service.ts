import { createHash } from "node:crypto";
import type { AiAutonomy, PlaybookActionType, Prisma, RuleChange, RuleChangeKind, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { notify, staffFor } from "@/lib/notifications";
import { canonicalJson } from "@/lib/rulebook/schema";
import { forgetRulebook, hashRulebook, parseStored } from "@/lib/rulebook/service";
import { setSetting, aiSettings } from "@/lib/settings";
import { KIND_LABEL, approvalBlock, fullyApproved, isPlatformKind, rejectBlock, sidesFor, type ContainmentProfile, type PlatformAiSettings, type Side } from "@/lib/changes/rules";

// Change control on the server (rules in lib/changes/rules.ts): a change is
// requested, approved by the sides it needs, then applied in one step,
// checking first that what it changes is still as it was when requested.
// Every request, approval, rejection and application goes into the audit
// chain with the change's hash, and the people who need to act are told.

export interface ChangeActor {
  id: string;
  name: string;
  role: UserRole;
  isClient: boolean;
  tenantId: string | null;
}

// HELIOS's own periodic review proposing a promotion. Deterministic code,
// not an AI agent: it can propose, never approve.
export const AUTOMATIC_REVIEW = { name: "automatic review" } as const;

// ---------------------------------------------------------------- payloads

// What approvers see: the lines that change against the version in force,
// and what the last 30 days of AI proposals would have become under it.
export interface RulebookImpact {
  diff: Array<{ path: string; kind: "changed" | "added" | "removed"; before?: string; after?: string }>;
  dryRun: { days: number; total: number; then: Record<string, number>; now: Record<string, number>; changed: number } | null;
}
export interface RulebookPayload { policyId: string; version: number; contentHash: string; againstVersion?: number | null; impact?: RulebookImpact }
export interface AllowlistAddPayload { kind: string; value: string; reason: string; owner: string; expiresAt: string | null }
export interface AllowlistRemovePayload { entryId: string; kind: string; value: string }
export interface AutonomyPayload { actionType: PlaybookActionType; from: number; to: number; stats?: unknown }
export interface ConsentPayload { from: AiAutonomy; to: AiAutonomy }
export interface ProfilePayload { key: "containment"; before: ContainmentProfile; after: ContainmentProfile; widening: string[] }
export interface SettingsPayload { before: PlatformAiSettings; after: PlatformAiSettings; widening: string[] }

type PayloadFor = {
  RULEBOOK_VERSION: RulebookPayload;
  ALLOWLIST_ADD: AllowlistAddPayload;
  ALLOWLIST_REMOVE: AllowlistRemovePayload;
  AUTONOMY_RAISE: AutonomyPayload;
  AI_CONSENT: ConsentPayload;
  AGENT_PROFILE: ProfilePayload;
  AI_SETTINGS: SettingsPayload;
};

export const changeHash = (kind: RuleChangeKind, tenantId: string | null, payload: unknown) => createHash("sha256").update(canonicalJson({ kind, tenantId, payload })).digest("hex");

// A pending change of the same kind for the same thing is replaced.
function sameSubject(kind: RuleChangeKind, a: unknown, b: unknown) {
  if (kind === "RULEBOOK_VERSION" || kind === "AI_CONSENT" || kind === "AI_SETTINGS" || kind === "AGENT_PROFILE") return true;
  if (kind === "AUTONOMY_RAISE") return (a as AutonomyPayload).actionType === (b as AutonomyPayload).actionType;
  if (kind === "ALLOWLIST_REMOVE") return (a as AllowlistRemovePayload).entryId === (b as AllowlistRemovePayload).entryId;
  const x = a as AllowlistAddPayload;
  const y = b as AllowlistAddPayload;
  return x.kind === y.kind && x.value.toLowerCase() === y.value.toLowerCase();
}

async function approverIds(change: Pick<RuleChange, "tenantId" | "kind">, side: Side) {
  if (side === "client") {
    const admins = await db.user.findMany({ where: { tenantId: change.tenantId, role: "CLIENT_ADMIN", active: true }, select: { id: true } });
    return admins.map((a) => a.id);
  }
  return staffFor(isPlatformKind(change.kind) ? ["ADMIN", "SOC_MANAGER"] : ["ADMIN", "SOC_MANAGER"]);
}

const where = (change: Pick<RuleChange, "tenantId">) => (change.tenantId ? "/changes" : "/changes?scope=platform");

// ---------------------------------------------------------------- request

export async function requestChange<K extends RuleChangeKind>(
  input: { tenantId: string | null; kind: K; summary: string; reason: string; payload: PayloadFor[K] },
  actor: ChangeActor | typeof AUTOMATIC_REVIEW,
): Promise<RuleChange> {
  const { tenantId, kind } = input;
  if (isPlatformKind(kind) !== !tenantId) throw new Error(isPlatformKind(kind) ? "Platform settings aren't a client's" : "A client's rule change needs the client");
  const reason = input.reason.trim();
  if (reason.length < 3) throw new Error("Say why the rules should change");
  const human = "id" in actor;
  if (human) {
    // A real, active person: no AI agent or token has a session to get here.
    const person = await db.user.findUnique({ where: { id: actor.id }, select: { active: true, tenantId: true } });
    if (!person?.active) throw new Error("Only active people can ask for a rule change");
    if (actor.isClient && person.tenantId !== tenantId) throw new Error("Not found");
  }
  const payload = JSON.parse(JSON.stringify(input.payload)) as Prisma.InputJsonValue;
  const payloadHash = changeHash(kind, tenantId, payload);
  // A client admin asking speaks for the client. The rulebook is the
  // exception: its version is signed explicitly, after reading it.
  const clientSelf = human && actor.isClient && actor.role === "CLIENT_ADMIN" && kind !== "RULEBOOK_VERSION";
  const now = new Date();

  const created = await db.$transaction(async (tx) => {
    const open = await tx.ruleChange.findMany({ where: { tenantId, kind, status: "PENDING" } });
    const replaced = open.filter((c) => sameSubject(kind, c.payload, payload));
    if (replaced.length) await tx.ruleChange.updateMany({ where: { id: { in: replaced.map((c) => c.id) } }, data: { status: "WITHDRAWN", decidedAt: now, decidedByName: "replaced by a newer request", decisionNote: "Replaced by a newer request for the same change" } });
    return tx.ruleChange.create({
      data: {
        tenantId,
        kind,
        summary: input.summary.slice(0, 1000),
        reason: reason.slice(0, 2000),
        payload,
        payloadHash,
        requestedById: human ? actor.id : null,
        requestedByName: actor.name,
        requestedByClient: human && actor.isClient,
        ...(clientSelf ? { clientApprovedById: actor.id, clientApprovedByName: actor.name, clientApprovedAt: now, clientApprovalNote: "Requested by the client's admin" } : {}),
      },
    });
  });
  await logAction({ actorId: human ? actor.id : undefined, action: "change.requested", detail: { changeId: created.id, tenantId, kind, summary: created.summary, hash: payloadHash, reason } });

  for (const side of sidesFor(kind)) {
    if (side === "client" && created.clientApprovedAt) continue;
    const ids = await approverIds(created, side);
    await notify(ids, { kind: "rulebook", title: `Rule change to approve: ${KIND_LABEL[kind]}`, body: `${created.summary}. ${side === "client" ? "Your approval and HELIOS's are both needed before it takes effect." : "It takes effect only once approved."}`, href: where(created), actorName: actor.name }, { exclude: human ? actor.id : null });
  }
  return created;
}

// ---------------------------------------------------------------- decide

export async function approveChange(changeId: string, side: Side, actor: ChangeActor, note = "") {
  const change = await db.ruleChange.findUnique({ where: { id: changeId } });
  if (!change || (actor.isClient && change.tenantId !== actor.tenantId)) throw new Error("Not found");
  const person = await db.user.findUnique({ where: { id: actor.id }, select: { active: true } });
  const block = approvalBlock(change, side, { ...actor, active: !!person?.active });
  if (block) throw new Error(block);
  const text = note.trim().slice(0, 1000);
  const onBehalf = side === "client" && !actor.isClient;
  if (onBehalf && text.length < 10) throw new Error("Record the client's instruction (who approved it, when and how)");
  const now = new Date();
  const data: Prisma.RuleChangeUpdateManyMutationInput =
    side === "client"
      ? { clientApprovedById: actor.id, clientApprovedByName: actor.name, clientApprovedAt: now, clientOnBehalf: onBehalf, clientApprovalNote: onBehalf ? `Recorded by ${actor.name} on the client's instruction: ${text}` : text || null }
      : { heliosApprovedById: actor.id, heliosApprovedByName: actor.name, heliosApprovedAt: now, heliosApprovalNote: text || null };
  // Only if nobody else gave this approval meanwhile.
  const { count } = await db.ruleChange.updateMany({ where: { id: changeId, status: "PENDING", ...(side === "client" ? { clientApprovedAt: null } : { heliosApprovedAt: null }) }, data });
  if (!count) throw new Error("Someone else decided on this change meanwhile; reload");
  await logAction({ actorId: actor.id, action: "change.approved", detail: { changeId, tenantId: change.tenantId, kind: change.kind, side, onBehalf, hash: change.payloadHash, note: text || null } });

  const updated = await db.ruleChange.findUniqueOrThrow({ where: { id: changeId } });
  if (!fullyApproved(updated)) {
    const waiting = sidesFor(updated.kind).find((s) => (s === "client" ? !updated.clientApprovedAt : !updated.heliosApprovedAt))!;
    await notify(await approverIds(updated, waiting), { kind: "rulebook", title: `Rule change to approve: ${KIND_LABEL[updated.kind]}`, body: `${updated.summary}. ${side === "client" ? "The client approved it" : "HELIOS approved it"}; it takes effect once ${waiting === "client" ? "the client approves" : "HELIOS approves"} too.`, href: where(updated), actorName: actor.name }, { exclude: actor.id });
    return { applied: false as const, change: updated };
  }
  return applyChange(updated, actor);
}

export async function rejectChange(changeId: string, actor: ChangeActor, note: string) {
  const change = await db.ruleChange.findUnique({ where: { id: changeId } });
  if (!change || (actor.isClient && change.tenantId !== actor.tenantId)) throw new Error("Not found");
  const block = rejectBlock(change, actor);
  if (block) throw new Error(block);
  const text = note.trim();
  if (text.length < 3) throw new Error("Say why it's turned down");
  await closeChange(change, "REJECTED", { id: actor.id, name: actor.name }, text);
  await logAction({ actorId: actor.id, action: "change.rejected", detail: { changeId, tenantId: change.tenantId, kind: change.kind, hash: change.payloadHash, note: text } });
  if (change.requestedById) await notify([change.requestedById], { kind: "rulebook", title: `Rule change turned down: ${KIND_LABEL[change.kind]}`, body: `${change.summary}. ${actor.name}: ${text}`, href: where(change), actorName: actor.name }, { exclude: actor.id });
}

export async function withdrawChange(changeId: string, actor: ChangeActor) {
  const change = await db.ruleChange.findUnique({ where: { id: changeId } });
  if (!change || (actor.isClient && change.tenantId !== actor.tenantId)) throw new Error("Not found");
  if (change.status !== "PENDING") throw new Error("This change isn't waiting for approval");
  if (change.requestedById !== actor.id) throw new Error("Only the person who asked can withdraw it");
  await closeChange(change, "WITHDRAWN", { id: actor.id, name: actor.name }, "Withdrawn by the requester");
  await logAction({ actorId: actor.id, action: "change.withdrawn", detail: { changeId, tenantId: change.tenantId, kind: change.kind } });
}

// Closes a change that won't apply, undoing what waiting for it held.
async function closeChange(change: RuleChange, status: "REJECTED" | "WITHDRAWN" | "STALE", by: { id: string | null; name: string }, note: string, tx: Prisma.TransactionClient = db) {
  await tx.ruleChange.updateMany({ where: { id: change.id, status: "PENDING" }, data: { status, decidedById: by.id, decidedByName: by.name, decidedAt: new Date(), decisionNote: note.slice(0, 1000) } });
  if (change.kind === "RULEBOOK_VERSION") {
    // The version goes back to being a draft its author can change.
    const p = change.payload as unknown as RulebookPayload;
    await tx.orgPolicy.updateMany({ where: { id: p.policyId, status: "AWAITING_SIGNATURE" }, data: { status: "DRAFT", submittedAt: null } });
  }
  if (change.kind === "AUTONOMY_RAISE" && change.tenantId) {
    const p = change.payload as unknown as AutonomyPayload;
    await tx.autonomyLevel.updateMany({ where: { tenantId: change.tenantId, actionType: p.actionType, proposedLevel: p.to }, data: { proposedLevel: null, proposedAt: null } });
  }
}

// When a draft is edited or thrown away, a pending approval of it lapses.
export async function withdrawRulebookChange(tenantId: string, policyId: string, by: { id: string; name: string }, note: string) {
  const open = await db.ruleChange.findMany({ where: { tenantId, kind: "RULEBOOK_VERSION", status: "PENDING" } });
  for (const c of open.filter((c) => (c.payload as unknown as RulebookPayload).policyId === policyId)) {
    await db.ruleChange.updateMany({ where: { id: c.id, status: "PENDING" }, data: { status: "WITHDRAWN", decidedById: by.id, decidedByName: by.name, decidedAt: new Date(), decisionNote: note } });
    await logAction({ actorId: by.id, action: "change.withdrawn", detail: { changeId: c.id, tenantId, kind: c.kind, note } });
  }
}

// ---------------------------------------------------------------- apply

class Stale extends Error {}

async function applyChange(change: RuleChange, actor: ChangeActor) {
  const now = new Date();
  try {
    await db.$transaction(async (tx) => {
      // Exactly once, however many approvals land together.
      const { count } = await tx.ruleChange.updateMany({ where: { id: change.id, status: "PENDING" }, data: { status: "APPLIED", appliedAt: now } });
      if (!count) throw new Stale("Already applied or closed");
      await applyPayload(tx, change, now);
    });
  } catch (err) {
    if (!(err instanceof Stale)) throw err;
    await closeChange(change, "STALE", { id: null, name: "HELIOS" }, err.message);
    await logAction({ actorId: actor.id, action: "change.stale", detail: { changeId: change.id, tenantId: change.tenantId, kind: change.kind, reason: err.message } });
    throw new Error(`It can't take effect: ${err.message}. Ask for the change again.`);
  }
  if (change.tenantId) forgetRulebook(change.tenantId);
  await logAction({ actorId: actor.id, action: "change.applied", detail: { changeId: change.id, tenantId: change.tenantId, kind: change.kind, summary: change.summary, hash: change.payloadHash, client: change.clientApprovedByName, helios: change.heliosApprovedByName } });
  if (change.kind === "RULEBOOK_VERSION") {
    const p = change.payload as unknown as RulebookPayload;
    await logAction({ actorId: actor.id, action: "rulebook.activated", detail: { tenantId: change.tenantId, version: p.version, hash: p.contentHash, client: change.clientApprovedByName, helios: change.heliosApprovedByName, onBehalf: change.clientOnBehalf } });
  }
  const told = new Set<string>([...(change.requestedById ? [change.requestedById] : []), ...(change.clientApprovedById ? [change.clientApprovedById] : []), ...(change.tenantId ? await approverIds(change, "client") : [])]);
  await notify(told, { kind: "rulebook", title: `Rule change in effect: ${KIND_LABEL[change.kind]}`, body: `${change.summary}. Approved by ${[change.clientApprovedByName, change.heliosApprovedByName].filter(Boolean).join(" and ")}.`, href: where(change), actorName: actor.name }, { exclude: actor.id });
  return { applied: true as const, change: await db.ruleChange.findUniqueOrThrow({ where: { id: change.id } }) };
}

async function applyPayload(tx: Prisma.TransactionClient, change: RuleChange, now: Date) {
  const tenantId = change.tenantId;
  switch (change.kind) {
    case "RULEBOOK_VERSION": {
      const p = change.payload as unknown as RulebookPayload;
      const pending = await tx.orgPolicy.findFirst({ where: { id: p.policyId, tenantId: tenantId!, status: "AWAITING_SIGNATURE" } });
      if (!pending) throw new Stale("that rulebook version is no longer waiting");
      // What was reviewed is what runs: the stored body must still match.
      if (pending.contentHash !== p.contentHash || hashRulebook(pending.body) !== p.contentHash) throw new Stale("that rulebook version changed after it was submitted");
      parseStored(pending);
      await tx.orgPolicy.updateMany({ where: { tenantId: tenantId!, status: "ACTIVE" }, data: { status: "SUPERSEDED" } });
      await tx.orgPolicy.update({
        where: { id: pending.id },
        data: {
          status: "ACTIVE",
          signedById: change.clientApprovedById,
          signedByName: change.clientApprovedByName,
          signedAt: change.clientApprovedAt,
          signatureNote: change.clientApprovalNote,
          heliosApprovedById: change.heliosApprovedById,
          heliosApprovedByName: change.heliosApprovedByName,
          heliosApprovedAt: change.heliosApprovedAt,
          effectiveFrom: now,
        },
      });
      return;
    }
    case "ALLOWLIST_ADD": {
      const p = change.payload as unknown as AllowlistAddPayload;
      const expiresAt = p.expiresAt ? new Date(p.expiresAt) : null;
      if (expiresAt && expiresAt <= now) throw new Stale("the entry's expiry has passed");
      await tx.policyAllowlistEntry.create({ data: { tenantId: tenantId!, kind: p.kind, value: p.value, reason: p.reason, owner: p.owner, expiresAt, createdById: change.requestedById } });
      return;
    }
    case "ALLOWLIST_REMOVE": {
      const p = change.payload as unknown as AllowlistRemovePayload;
      const { count } = await tx.policyAllowlistEntry.deleteMany({ where: { id: p.entryId, tenantId: tenantId! } });
      if (!count) throw new Stale("that allowlist entry is already gone");
      return;
    }
    case "AUTONOMY_RAISE": {
      const p = change.payload as unknown as AutonomyPayload;
      const { count } = await tx.autonomyLevel.updateMany({
        where: { tenantId: tenantId!, actionType: p.actionType, level: p.from },
        data: { level: p.to, reason: `Raised with the approval of ${change.clientApprovedByName} (client) and ${change.heliosApprovedByName} (HELIOS)`, changedByName: change.heliosApprovedByName ?? "HELIOS", proposedLevel: null, proposedAt: null },
      });
      if (!count) throw new Stale("the level changed since it was proposed");
      return;
    }
    case "AI_CONSENT": {
      const p = change.payload as unknown as ConsentPayload;
      const { count } = await tx.tenant.updateMany({ where: { id: tenantId!, aiAutonomyCap: p.from }, data: { aiAutonomyCap: p.to } });
      if (!count) throw new Stale("the client's consent changed since it was asked for");
      return;
    }
    case "AGENT_PROFILE": {
      const p = change.payload as unknown as ProfilePayload;
      const row = await tx.aiAgentProfile.findUnique({ where: { key: p.key } });
      const current: ContainmentProfile | null = row ? { enabled: row.enabled, autonomy: row.autonomy, minConfidence: row.minConfidence, allowedActions: row.allowedActions } : null;
      if (current && canonicalJson(sortProfile(current)) !== canonicalJson(sortProfile(p.before))) throw new Stale("the containment agent's profile changed since it was asked for");
      await tx.aiAgentProfile.update({ where: { key: p.key }, data: { enabled: p.after.enabled, autonomy: p.after.autonomy, minConfidence: p.after.minConfidence, allowedActions: p.after.allowedActions } });
      return;
    }
    case "AI_SETTINGS": {
      const p = change.payload as unknown as SettingsPayload;
      const current = await aiSettings();
      if (canonicalJson(current) !== canonicalJson(p.before)) throw new Stale("the AI settings changed since it was asked for");
      // Settings live outside this transaction's client; written after the
      // change is marked applied, which the surrounding transaction holds.
      await setSetting("ai.killSwitch", p.after.killSwitch, change.heliosApprovedById ?? undefined);
      await setSetting("ai.firstResponse.enabled", p.after.firstResponse, change.heliosApprovedById ?? undefined);
      await setSetting("ai.firstResponse.minSeverity", p.after.minSeverity as never, change.heliosApprovedById ?? undefined);
      await setSetting("ai.maxAutoActionsPerHour", p.after.maxAutoActionsPerHour, change.heliosApprovedById ?? undefined);
      return;
    }
  }
}

const sortProfile = (p: ContainmentProfile) => ({ ...p, allowedActions: [...p.allowedActions].sort() });

// ---------------------------------------------------------------- reading

export async function listChanges(scope: { tenantId?: string | null; platform?: boolean }, status: "pending" | "history", take = 100) {
  const tenantFilter: Prisma.RuleChangeWhereInput = scope.platform ? { tenantId: null } : scope.tenantId ? { tenantId: scope.tenantId } : {};
  return db.ruleChange.findMany({
    where: { ...tenantFilter, ...(status === "pending" ? { status: "PENDING" } : { status: { not: "PENDING" } }) },
    orderBy: { createdAt: "desc" },
    take,
    include: { tenant: { select: { name: true } } },
  });
}

export async function pendingChangeCount(user: { isClient: boolean; tenantId: string | null }) {
  return db.ruleChange.count({ where: { status: "PENDING", ...(user.isClient ? { tenantId: user.tenantId ?? "__none__" } : {}) } });
}
