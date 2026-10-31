import type { RuleChange } from "@prisma/client";

import { KIND_LABEL, approvalBlock, rejectBlock, sidesFor, type Approver } from "@/lib/changes/rules";

// A rule change as the page shows it to one person: what it is, who has
// approved it, and which buttons that person gets (the server re-checks).
export interface ChangeView {
  id: string;
  kind: RuleChange["kind"];
  kindLabel: string;
  status: RuleChange["status"];
  summary: string;
  reason: string;
  tenantName: string | null;
  platform: boolean;
  requestedByName: string;
  requestedByClient: boolean;
  requestedAt: string;
  needsClient: boolean;
  client: { byName: string | null; at: string | null; onBehalf: boolean; note: string | null };
  helios: { byName: string | null; at: string | null; note: string | null };
  decidedByName: string | null;
  decidedAt: string | null;
  decisionNote: string | null;
  appliedAt: string | null;
  hash: string;
  href: string | null;
  // A rulebook version's lines that change, and its dry run.
  impact: { againstVersion: number | null; diff: Array<{ path: string; kind: string; before?: string; after?: string }>; dryRun: { days: number; total: number; then: Record<string, number>; now: Record<string, number>; changed: number } | null } | null;
  can: { client: boolean; clientOnBehalf: boolean; helios: boolean; reject: boolean; withdraw: boolean };
  // Why this person can't approve, when they'd expect to.
  blocked: string | null;
}

export function changeView(c: RuleChange & { tenant?: { name: string } | null }, user: Approver & { name?: string | null }): ChangeView {
  const clientBlock = sidesFor(c.kind).includes("client") ? approvalBlock(c, "client", user) : "n/a";
  const heliosBlock = approvalBlock(c, "helios", user);
  const iso = (d: Date | null) => d?.toISOString() ?? null;
  const href = c.kind === "RULEBOOK_VERSION" || c.kind === "ALLOWLIST_ADD" || c.kind === "ALLOWLIST_REMOVE" || c.kind === "AUTONOMY_RAISE" ? (user.isClient ? "/rulebook" : `/rulebook?tenant=${c.tenantId}`) : c.kind === "AI_CONSENT" ? (user.isClient ? "/" : `/tenants/${c.tenantId}`) : "/ai";
  return {
    id: c.id,
    kind: c.kind,
    kindLabel: KIND_LABEL[c.kind],
    status: c.status,
    summary: c.summary,
    reason: c.reason,
    tenantName: c.tenant?.name ?? null,
    platform: !c.tenantId,
    requestedByName: c.requestedByName,
    requestedByClient: c.requestedByClient,
    requestedAt: c.createdAt.toISOString(),
    needsClient: sidesFor(c.kind).includes("client"),
    client: { byName: c.clientApprovedByName, at: iso(c.clientApprovedAt), onBehalf: c.clientOnBehalf, note: c.clientApprovalNote },
    helios: { byName: c.heliosApprovedByName, at: iso(c.heliosApprovedAt), note: c.heliosApprovalNote },
    decidedByName: c.decidedByName,
    decidedAt: iso(c.decidedAt),
    decisionNote: c.decisionNote,
    appliedAt: iso(c.appliedAt),
    hash: c.payloadHash,
    href,
    impact: c.kind === "RULEBOOK_VERSION" ? impactOf(c.payload) : null,
    can: {
      client: clientBlock === null,
      clientOnBehalf: clientBlock === null && !user.isClient,
      helios: heliosBlock === null,
      reject: rejectBlock(c, user) === null && c.requestedById !== user.id,
      withdraw: c.status === "PENDING" && c.requestedById === user.id,
    },
    blocked: c.status !== "PENDING" || clientBlock === null || heliosBlock === null ? null : waitingNote(c, user, user.isClient ? clientBlock : heliosBlock),
  };
}

// What the person is waiting for, said plainly.
function waitingNote(c: RuleChange, user: Approver, block: string): string | null {
  const needsClient = sidesFor(c.kind).includes("client");
  if (needsClient && c.clientApprovedAt && !c.heliosApprovedAt && (user.isClient || block.startsWith("Someone other") || block.startsWith("You recorded"))) return `Waiting for HELIOS's approval${user.isClient ? "" : ` from someone other than ${c.requestedById === user.id ? "you" : c.requestedByName}`}.`;
  if (needsClient && !c.clientApprovedAt && c.heliosApprovedAt) return "Waiting for the client's approval.";
  return block === "n/a" ? null : block;
}

type Impact = NonNullable<ChangeView["impact"]>;
function impactOf(payload: unknown): ChangeView["impact"] {
  const p = payload as { againstVersion?: number | null; impact?: { diff?: Impact["diff"]; dryRun?: Impact["dryRun"] } } | null;
  if (!p?.impact) return null;
  return { againstVersion: p.againstVersion ?? null, diff: p.impact.diff ?? [], dryRun: p.impact.dryRun ?? null };
}
