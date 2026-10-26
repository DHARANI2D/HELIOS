import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { activeRulebook } from "@/lib/rulebook/service";
import { masterKeySource } from "@/lib/secrets";
import { parseProtections } from "@/lib/endpoints/controls";
import { DATA_CATEGORIES, median } from "@/lib/ingest/health";

// ISO/IEC 27001:2022 Annex A controls that HELIOS produces evidence for, and
// what it shows for each over a period: real counts from the platform's own
// records, with a link to where they come from. A control with nothing
// behind it says so (a gap), rather than claiming it's met. Evidence for an
// auditor, not a certification.

export type EvidenceStatus = "evidenced" | "partial" | "gap";

export interface Evidence {
  label: string;
  value: string;
  href?: string;
}

export interface ControlEvidence {
  id: string;
  name: string;
  status: EvidenceStatus;
  evidence: Evidence[];
  note?: string;
}

const DAY = 86_400_000;
const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "—");
const mins = (ms: number) => (ms < 3_600_000 ? `${Math.round(ms / 60_000)} min` : `${(ms / 3_600_000).toFixed(1)} h`);
// All of a population covered, some, or none.
const share = (covered: number, total: number): EvidenceStatus => (total > 0 && covered === total ? "evidenced" : covered > 0 ? "partial" : "gap");
const status = (ok: boolean[], need = ok.length): EvidenceStatus => {
  const n = ok.filter(Boolean).length;
  return n >= need ? "evidenced" : n > 0 ? "partial" : "gap";
};

export async function evidenceMap(tenantId: string | null, days = 90, now = new Date()): Promise<ControlEvidence[]> {
  const since = new Date(now.getTime() - days * DAY);
  const t = tenantId ? { tenantId } : {};
  const caseWhere: Prisma.CaseWhereInput = { ...t, createdAt: { gte: since } };

  const scopeTenants = tenantId ? [{ id: tenantId }] : await db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true } });
  const [cases, actions, notices, sources, endpoints, timeline, audit, staff, clients, rulebooks, keys, indicators, playbooks, outcomes] = await Promise.all([
    db.case.findMany({ where: caseWhere, select: { createdAt: true, acknowledgedAt: true, slaDueAt: true, containedAt: true, resolvedAt: true, disposition: true, rootCauseNarrative: true, status: true }, take: 20_000 }),
    db.responseAction.findMany({ where: { ...t, createdAt: { gte: since }, status: { in: ["EXECUTED", "ROLLED_BACK", "MANUAL_REQUIRED", "FAILED"] } }, select: { status: true, result: true }, take: 20_000 }),
    db.regulatoryNotice.findMany({ where: { ...t, createdAt: { gte: since } }, select: { status: true, dueAt: true, submittedAt: true } }),
    db.integration.findMany({ where: { ...t, enabled: true }, select: { category: true, lastEventAt: true, quietSince: true, quietAfterMinutes: true } }),
    db.endpoint.findMany({ where: t, select: { protections: true }, take: 50_000 }),
    db.timelineEntry.count({ where: { case: caseWhere } }),
    db.auditLog.count({ where: { createdAt: { gte: since }, ...(tenantId ? { case: { tenantId } } : {}) } }),
    db.user.findMany({ where: { active: true, tenantId: null }, select: { mfaEnabledAt: true } }),
    db.user.findMany({ where: { active: true, tenantId: tenantId ?? { not: null } }, select: { mfaEnabledAt: true } }),
    Promise.all(scopeTenants.map((x) => activeRulebook(x.id))),
    db.tenantKey.findMany({ where: { ...(tenantId ? { tenantId } : { tenantId: { in: scopeTenants.map((x) => x.id) } }), retiredAt: null, destroyedAt: null }, orderBy: { version: "desc" }, select: { tenantId: true, version: true, createdAt: true } }),
    db.caseIndicator.count({ where: { case: caseWhere } }),
    db.playbook.count({ where: { enabled: true } }),
    db.aiDecisionOutcome.count({ where: { ...t, createdAt: { gte: since } } }),
  ]);

  const acked = cases.filter((c) => c.acknowledgedAt);
  const ackTimes = acked.map((c) => c.acknowledgedAt!.getTime() - c.createdAt.getTime());
  const slaKnown = acked.filter((c) => c.slaDueAt);
  const slaMet = slaKnown.filter((c) => c.acknowledgedAt! <= c.slaDueAt!).length;
  const closed = cases.filter((c) => c.resolvedAt || c.status === "FALSE_POSITIVE" || c.status === "RESOLVED");
  const disposed = cases.filter((c) => c.disposition);
  const withRca = closed.filter((c) => c.rootCauseNarrative);
  const contained = cases.filter((c) => c.containedAt);
  const containTimes = contained.map((c) => c.containedAt!.getTime() - c.createdAt.getTime());
  const executed = actions.filter((a) => a.status === "EXECUTED" || a.status === "ROLLED_BACK");
  const verified = executed.filter((a) => !!(a.result as { verifiedAt?: string } | null)?.verifiedAt);
  const filed = notices.filter((n) => n.status === "SUBMITTED");
  const onTime = filed.filter((n) => !n.dueAt || n.submittedAt! <= n.dueAt);
  const overdue = notices.filter((n) => n.status !== "SUBMITTED" && n.status !== "NOT_REQUIRED" && n.dueAt && n.dueAt < now);
  const dataSources = sources.filter((s) => DATA_CATEGORIES.has(s.category));
  const live = dataSources.filter((s) => s.lastEventAt && !s.quietSince && now.getTime() - s.lastEventAt.getTime() < DAY);
  const quiet = dataSources.filter((s) => s.quietSince);
  const edr = endpoints.filter((e) => parseProtections(e.protections).edr?.status === "active");
  const staffMfa = staff.filter((u) => u.mfaEnabledAt).length;
  const clientMfa = clients.filter((u) => u.mfaEnabledAt).length;
  const casesHref = "/cases";

  // Per-client settings: the selected client's own, or how many clients
  // have each across the platform.
  const n = scopeTenants.length;
  const books = rulebooks.map((r) => r?.body ?? null);
  const count = (f: (b: NonNullable<(typeof books)[number]>) => boolean) => books.filter((b) => b && f(b)).length;
  const named = (c: { name: string; email: string; phone: string }) => !!c.name && !!(c.email || c.phone);
  const certIn = count((b) => b.obligations.regulatedEntity);
  const certInNamed = count((b) => b.obligations.regulatedEntity && named(b.obligations.certInContact));
  const dpdp = count((b) => b.obligations.dpdpFiduciary);
  const dpdpNamed = count((b) => b.obligations.dpdpFiduciary && named(b.obligations.dpdpContact));
  const withBook = books.filter(Boolean).length;
  const withChain = count((b) => b.approvers.chain.length > 0);
  // No rulebook means the default, which masks personal data.
  const masked = books.filter((b) => !b || b.dataHandling.redactPii).length;
  const flagged = count((b) => b.obligations.regulatedEntity || b.obligations.dpdpFiduciary);
  const keyed = new Set(keys.map((k) => k.tenantId)).size;
  const of = (x: number) => `${x} of ${n} client${n === 1 ? "" : "s"}`;
  const book = tenantId ? rulebooks[0] : null;
  const ob = book?.body.obligations;
  const reviewDue = book?.signedAt ? new Date(book.signedAt.getTime() + book.body.reviewEveryDays * DAY) : null;
  const every = (x: number) => n > 0 && x === n;

  return [
    {
      id: "5.5",
      name: "Contact with authorities",
      status: status([certIn > 0 && certInNamed === certIn, filed.length === 0 || onTime.length === filed.length], 2),
      evidence: [
        tenantId
          ? { label: "CERT-In point of contact", value: ob?.regulatedEntity ? (ob.certInContact.name ? `${ob.certInContact.name}${ob.certInContact.email ? ` (${ob.certInContact.email})` : ""}` : "Not named in the rulebook") : "CERT-In reporting isn't set for this client", href: "/rulebook" }
          : { label: "CERT-In point of contact named", value: `${certInNamed} of the ${certIn} client${certIn === 1 ? "" : "s"} CERT-In applies to`, href: "/rulebook" },
        { label: "Regulatory notices filed", value: `${filed.length} (${onTime.length} on time)` },
        { label: "Overdue now", value: String(overdue.length), href: "/compliance" },
      ],
    },
    {
      id: "5.7",
      name: "Threat intelligence",
      status: status([indicators > 0]),
      evidence: [{ label: "Indicators linked to cases", value: indicators.toLocaleString(), href: "/threat-intel" }],
    },
    {
      id: "5.24",
      name: "Information security incident management planning and preparation",
      status: status([every(withBook), playbooks > 0, every(withChain)], 3),
      evidence: [
        { label: "Rulebook in force", value: tenantId ? (book ? `v${book.version}${book.signedByName ? `, signed by ${book.signedByName}` : ""}${reviewDue ? ` · review due ${reviewDue.toISOString().slice(0, 10)}` : ""}` : "None") : of(withBook), href: "/rulebook" },
        { label: "Approver chain", value: tenantId ? `${book?.body.approvers.chain.length ?? 0} people` : of(withChain) },
        { label: "Response playbooks enabled", value: String(playbooks), href: "/playbooks" },
      ],
    },
    {
      id: "5.25",
      name: "Assessment and decision on information security events",
      status: status([cases.length > 0, acked.length > 0, disposed.length > 0], 3),
      evidence: [
        { label: "Cases opened", value: cases.length.toLocaleString(), href: casesHref },
        { label: "Acknowledged", value: `${acked.length.toLocaleString()} · median ${ackTimes.length ? mins(median(ackTimes)) : "—"}` },
        { label: "Acknowledged within SLA", value: `${pct(slaMet, slaKnown.length)} of ${slaKnown.length}` },
        { label: "Closed with a recorded disposition", value: `${disposed.length.toLocaleString()} of ${closed.length.toLocaleString()} closed` },
      ],
    },
    {
      id: "5.26",
      name: "Response to information security incidents",
      status: status([contained.length > 0 || executed.length > 0, executed.length === 0 || verified.length > 0], 2),
      evidence: [
        { label: "Cases contained", value: `${contained.length.toLocaleString()} · median ${containTimes.length ? mins(median(containTimes)) : "—"} from detection` },
        { label: "Containment carried out", value: executed.length.toLocaleString() },
        { label: "Confirmed by the vendor's own state", value: `${verified.length.toLocaleString()} (${pct(verified.length, executed.length)})` },
      ],
    },
    {
      id: "5.27",
      name: "Learning from information security incidents",
      status: status([withRca.length > 0, outcomes > 0], 2),
      evidence: [
        { label: "Closed cases with a root cause written", value: `${withRca.length.toLocaleString()} of ${closed.length.toLocaleString()}` },
        { label: "AI decisions compared with the analyst's call", value: outcomes.toLocaleString(), href: "/ai" },
      ],
    },
    {
      id: "5.28",
      name: "Collection of evidence",
      status: status([audit > 0, timeline > 0], 2),
      evidence: [
        { label: "Audit chain entries (hash-linked)", value: audit.toLocaleString(), href: "/audit" },
        { label: "Case timeline entries", value: timeline.toLocaleString() },
      ],
      note: "Each audit entry carries the hash of the one before it; the Audit Log page verifies the whole chain.",
    },
    {
      id: "5.31",
      name: "Legal, statutory, regulatory and contractual requirements",
      status: every(flagged) ? "evidenced" : flagged > 0 ? "partial" : "gap",
      evidence: [
        { label: "CERT-In reporting", value: tenantId ? (ob?.regulatedEntity ? `Applies, from ${ob.certInMinSeverity.toLowerCase()} severity` : "Not set") : `Set for ${of(certIn)}`, href: "/rulebook" },
        { label: "DPDP breach notification", value: tenantId ? (ob?.dpdpFiduciary ? "Data Fiduciary" : "Not set") : `Set for ${of(dpdp)}` },
      ],
    },
    {
      id: "5.34",
      name: "Privacy and protection of PII",
      status: status([every(masked), dpdp > 0 && dpdpNamed === dpdp], 2),
      evidence: [
        { label: "Personal data masked for cloud AI models", value: tenantId ? (masked ? "Yes" : "No") : of(masked) },
        { label: "Contact for affected people named", value: tenantId ? (ob?.dpdpFiduciary ? ob.dpdpContact.name || "Not named" : "Not a Data Fiduciary") : `${dpdpNamed} of the ${dpdp} Data Fiduciar${dpdp === 1 ? "y" : "ies"}` },
      ],
    },
    {
      id: "8.5",
      name: "Secure authentication",
      status: share(staffMfa + clientMfa, staff.length + clients.length),
      evidence: [
        { label: "SOC staff with two-step sign-in", value: `${staffMfa} of ${staff.length}`, href: "/team" },
        { label: "Client users with two-step sign-in", value: `${clientMfa} of ${clients.length}` },
      ],
    },
    {
      id: "8.7",
      name: "Protection against malware",
      status: share(edr.length, endpoints.length),
      evidence: [{ label: "Endpoints with EDR active", value: `${edr.length.toLocaleString()} of ${endpoints.length.toLocaleString()} (${pct(edr.length, endpoints.length)})`, href: "/endpoints" }],
    },
    {
      id: "8.15",
      name: "Logging",
      status: status([dataSources.length > 0, live.length === dataSources.length && dataSources.length > 0], 2),
      evidence: [
        { label: "Log sources connected", value: String(dataSources.length), href: "/integrations" },
        { label: "Sending in the last day", value: `${live.length} of ${dataSources.length}` },
      ],
      note: "Retention isn't evidenced yet: CERT-In asks for 180 days of logs kept in India.",
    },
    {
      id: "8.16",
      name: "Monitoring activities",
      status: status([dataSources.length > 0, dataSources.some((s) => s.quietAfterMinutes !== 0)], 2),
      evidence: [
        { label: "Sources watched for going quiet", value: `${dataSources.filter((s) => s.quietAfterMinutes !== 0).length} of ${dataSources.length}` },
        { label: "Quiet right now", value: String(quiet.length) },
      ],
    },
    {
      id: "8.17",
      name: "Clock synchronization",
      status: "gap",
      evidence: [{ label: "Client systems' clocks", value: "Not evidenced by HELIOS" }],
      note: "HELIOS keeps every event in UTC as received. CERT-In asks entities to sync their clocks to the NTP servers of NIC or NPL; that's on the client's systems.",
    },
    {
      id: "8.24",
      name: "Use of cryptography",
      status: every(keyed) && masterKeySource() !== "derived-from-auth-secret" ? "evidenced" : keyed > 0 || masterKeySource() !== "derived-from-auth-secret" ? "partial" : "gap",
      evidence: [
        { label: "Master key", value: masterKeySource() === "aws-kms" ? "Held in AWS KMS" : masterKeySource() === "environment" ? "Set in the environment" : "Derived from the sign-in secret (set a dedicated key)" },
        tenantId
          ? { label: "Client's own data key", value: keys[0] ? `Version ${keys[0].version}, since ${keys[0].createdAt.toISOString().slice(0, 10)}` : "Not adopted" }
          : { label: "Clients with their own data key", value: of(keyed) },
      ],
    },
  ];
}
