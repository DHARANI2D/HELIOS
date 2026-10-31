import type { AiAutonomy, PlaybookActionType, RuleChangeKind, UserRole } from "@prisma/client";

import { can } from "@/lib/rbac";

// Change control for the rules containment runs under. Pure: which
// approvals a change needs, who may give them, and whether a change widens
// what the AI may do. lib/changes/service.ts applies it.
//
// The principle: rules decide what the AI may do, people decide the rules.
// - A client's rules (its rulebook, its allowlist, the AI's autonomy and the
//   client's consent) change only with the client's approval AND HELIOS's.
// - Platform AI settings (the containment agent's profile, the kill switch,
//   rate limits) change only with a second HELIOS approver's.
// - Nobody gives HELIOS's approval to their own request. A client admin's
//   own request carries the client's approval: the client is the one asking.
// - Requests and approvals come from signed-in people only. No AI agent has
//   a session, an account or a tool that reaches any of this.
// - Taking power away from the AI (kill switch on, lowering autonomy or
//   consent, a narrower profile or limit) applies at once: stopping must
//   never wait for a signature.

export type Side = "client" | "helios";

export const KIND_LABEL: Record<RuleChangeKind, string> = {
  RULEBOOK_VERSION: "Rulebook version",
  ALLOWLIST_ADD: "Allowlist entry added",
  ALLOWLIST_REMOVE: "Allowlist entry removed",
  AUTONOMY_RAISE: "AI autonomy raised",
  AI_CONSENT: "AI containment consent raised",
  AGENT_PROFILE: "Containment agent widened",
  AI_SETTINGS: "Platform AI limits widened",
};

const PLATFORM_KINDS: RuleChangeKind[] = ["AGENT_PROFILE", "AI_SETTINGS"];

export const isPlatformKind = (kind: RuleChangeKind) => PLATFORM_KINDS.includes(kind);

// The approvals a change needs before it takes effect.
export function sidesFor(kind: RuleChangeKind): Side[] {
  return isPlatformKind(kind) ? ["helios"] : ["client", "helios"];
}

export interface Approver {
  id: string;
  role: UserRole;
  isClient: boolean;
  tenantId: string | null;
  active?: boolean;
}

export interface ChangeState {
  kind: RuleChangeKind;
  tenantId: string | null;
  status: string;
  requestedById: string | null;
  clientApprovedAt: Date | null;
  clientApprovedById: string | null;
  clientOnBehalf: boolean;
  heliosApprovedAt: Date | null;
  heliosApprovedById: string | null;
}

// May this person act for the client on this change at all?
function speaksForClient(change: ChangeState, user: Approver): string | null {
  if (user.isClient) {
    if (user.tenantId !== change.tenantId) return "Not your organisation's change";
    if (!can(user, "rulebook.sign")) return "Only the client's admins approve rule changes";
    return null;
  }
  // Staff record the client's approval on its instruction.
  return can(user, "rulebook.sign") ? null : "You can't record the client's approval";
}

// May this person act for HELIOS on this change at all?
function speaksForHelios(change: ChangeState, user: Approver): string | null {
  if (user.isClient) return "Only HELIOS approvers give HELIOS's approval";
  return can(user, isPlatformKind(change.kind) ? "ai.configure" : "rulebook.sign") ? null : "You can't approve rule changes for HELIOS";
}

// Whether this person may give this side's approval, and why not.
export function approvalBlock(change: ChangeState, side: Side, user: Approver): string | null {
  if (change.status !== "PENDING") return "This change isn't waiting for approval";
  if (user.active === false) return "Your account is inactive";
  if (!sidesFor(change.kind).includes(side)) return "This change doesn't need that approval";
  if (side === "client") {
    if (change.clientApprovedAt) return "The client has already approved it";
    const block = speaksForClient(change, user);
    if (block) return block;
    // Two different people: whoever approved for HELIOS can't also stand in for the client.
    if (!user.isClient && change.heliosApprovedById === user.id) return "You gave HELIOS's approval; the client's must come from them or from another person recording their instruction";
    return null;
  }
  if (change.heliosApprovedAt) return "HELIOS has already approved it";
  const block = speaksForHelios(change, user);
  if (block) return block;
  if (change.requestedById === user.id) return "Someone other than the requester gives HELIOS's approval";
  if (change.clientOnBehalf && change.clientApprovedById === user.id) return "You recorded the client's approval; another HELIOS approver gives HELIOS's";
  return null;
}

export function fullyApproved(change: Pick<ChangeState, "kind" | "clientApprovedAt" | "heliosApprovedAt">) {
  return sidesFor(change.kind).every((s) => (s === "client" ? !!change.clientApprovedAt : !!change.heliosApprovedAt));
}

// Turning a change down: anyone who speaks for a side it needs. The
// requester withdraws instead.
export function rejectBlock(change: ChangeState, user: Approver): string | null {
  if (change.status !== "PENDING") return "This change isn't waiting for approval";
  const sides = sidesFor(change.kind);
  const ok = sides.some((s) => (s === "client" ? speaksForClient(change, user) : speaksForHelios(change, user)) === null);
  return ok ? null : "You can't decide on this change";
}

// ---------------------------------------------------------------- widening

const AUTONOMY_RANK: Record<AiAutonomy, number> = { OFF: 0, SUGGEST: 1, CONTAIN_WITH_APPROVAL: 2, AUTO_CONTAIN: 3 };
export const autonomyWidens = (from: AiAutonomy, to: AiAutonomy) => AUTONOMY_RANK[to] > AUTONOMY_RANK[from];

export interface ContainmentProfile {
  enabled: boolean;
  autonomy: AiAutonomy;
  minConfidence: number;
  allowedActions: PlaybookActionType[];
}

// What in a change to the containment agent's profile gives it more room.
export function profileWidening(before: ContainmentProfile, after: ContainmentProfile): string[] {
  const out: string[] = [];
  if (after.enabled && !before.enabled) out.push("turns the agent on");
  if (autonomyWidens(before.autonomy, after.autonomy)) out.push(`autonomy ${before.autonomy} → ${after.autonomy}`);
  if (after.minConfidence < before.minConfidence) out.push(`confidence bar ${Math.round(before.minConfidence * 100)}% → ${Math.round(after.minConfidence * 100)}%`);
  const added = after.allowedActions.filter((a) => !before.allowedActions.includes(a));
  if (added.length) out.push(`pre-approves ${added.join(", ")}`);
  return out;
}

export interface PlatformAiSettings {
  killSwitch: boolean;
  firstResponse: boolean;
  minSeverity: string;
  maxAutoActionsPerHour: number;
}

const SEVERITY_RANK: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function settingsWidening(before: PlatformAiSettings, after: PlatformAiSettings): string[] {
  const out: string[] = [];
  if (before.killSwitch && !after.killSwitch) out.push("turns the kill switch off");
  if (after.firstResponse && !before.firstResponse) out.push("turns AI first response on");
  if ((SEVERITY_RANK[after.minSeverity] ?? 0) < (SEVERITY_RANK[before.minSeverity] ?? 0)) out.push(`AI first response from ${after.minSeverity} (was ${before.minSeverity})`);
  if (after.maxAutoActionsPerHour > before.maxAutoActionsPerHour) out.push(`automatic actions per hour ${before.maxAutoActionsPerHour} → ${after.maxAutoActionsPerHour}`);
  return out;
}

// The person behind a session, as change control records them.
export function changeActorOf(user: { id: string; name?: string | null; email?: string | null; role: UserRole; isClient: boolean; tenantId: string | null }) {
  return { id: user.id, name: user.name ?? user.email ?? "user", role: user.role, isClient: user.isClient, tenantId: user.tenantId };
}
