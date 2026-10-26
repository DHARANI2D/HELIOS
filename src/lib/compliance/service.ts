import { createElement } from "react";
import type { Prisma, RegulatoryNotice, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { caseAudience, notify, staffFor } from "@/lib/notifications";
import { getSetting } from "@/lib/settings";
import { sendMail } from "@/lib/mail";
import { renderPdf } from "@/lib/pdf/kit";
import { activeRulebook } from "@/lib/rulebook/service";
import { EMPTY_RULEBOOK, type Rulebook } from "@/lib/rulebook/schema";
import { assetTypeLabel } from "@/lib/assets/inventory";
import type { AssetClass } from "@/lib/assets/surface";
import { ACTION_LABEL } from "@/lib/response/executor";
import type { SessionUser } from "@/lib/session";
import { CERT_IN_CONTACT, atLeast, certInLabel, classifyIncident, isCertInCode, type CertInMatch, type IncidentFacts } from "@/lib/compliance/cert-in";
import { DPDP_REPORT_HOURS } from "@/lib/compliance/dpdp";
import { NOTICE_LABEL, certInEmail, missingFields, noticeDue, parseContent, reminderStage, type NoticeContent, type SubmitChannel } from "@/lib/compliance/notices";

// Regulatory reporting on the server. The rules propose (a case of an
// Annexure I type at the client's threshold starts the CERT-In clock; an
// analyst can start it on any case, and starts the DPDP workflow once
// personal data is involved); the SOC drafts from what the case already
// holds; the client approves; the filing is recorded, or sent from here by
// email. Every step is in the audit chain and on the case's timeline, and a
// notice approved and then edited goes back for approval.

const OPEN: RegulatoryNotice["status"][] = ["DRAFT", "AWAITING_APPROVAL", "APPROVED"];
const HOUR = 3_600_000;

async function rulebookFor(tenantId: string): Promise<Rulebook> {
  return (await activeRulebook(tenantId))?.body ?? EMPTY_RULEBOOK;
}

// ---------------------------------------------------------------- facts

async function loadCase(caseId: string) {
  return db.case.findUniqueOrThrow({
    where: { id: caseId },
    include: {
      tenant: { select: { id: true, name: true, industry: true } },
      detections: { select: { source: true, title: true }, take: 100 },
      mitreTechniques: { include: { technique: { select: { name: true } } } },
      indicators: { include: { indicator: { select: { type: true, value: true, maliciousScore: true } } }, take: 100 },
      responseActions: { where: { status: { in: ["EXECUTED", "MANUAL_REQUIRED", "ROLLED_BACK"] } }, orderBy: { createdAt: "asc" } },
    },
  });
}
type LoadedCase = Awaited<ReturnType<typeof loadCase>>;

// The client's systems a case touches, from its events and metadata, as
// the inventory knows them.
async function caseAssets(kase: LoadedCase) {
  const meta = (kase.metadata ?? {}) as Record<string, unknown>;
  const events = await db.securityEvent.findMany({ where: { caseId: kase.id, hostName: { not: null } }, select: { hostName: true }, distinct: ["hostName"], take: 50 });
  const names = new Set<string>(events.map((e) => e.hostName!.toLowerCase()));
  for (const k of ["hostName", "hostname"]) if (typeof meta[k] === "string") names.add((meta[k] as string).toLowerCase());
  if (meta.riskObjectType === "host" && typeof meta.riskObject === "string") names.add(meta.riskObject.toLowerCase());
  if (!kase.tenantId || names.size === 0) return { known: [], unknown: [...names] };
  const known = await db.endpoint.findMany({
    where: { tenantId: kase.tenantId, hostname: { in: [...names], mode: "insensitive" } },
    select: { hostname: true, ipAddress: true, os: true, assetClass: true, assetType: true, criticality: true },
  });
  const seen = new Set(known.map((e) => e.hostname.toLowerCase()));
  return { known, unknown: [...names].filter((n) => !seen.has(n)) };
}

export async function incidentFacts(kase: LoadedCase): Promise<{ facts: IncidentFacts; assets: Awaited<ReturnType<typeof caseAssets>> }> {
  const assets = await caseAssets(kase);
  return {
    assets,
    facts: {
      sourceType: kase.sourceType,
      domain: kase.domain,
      severity: kase.severity,
      verdict: kase.verdict,
      techniques: kase.mitreTechniques.map((t) => t.techniqueId),
      detectionSources: kase.detections.map((d) => d.source),
      titles: [kase.title, ...kase.detections.map((d) => d.title)],
      assets: assets.known.map((a) => ({ hostname: a.hostname, assetClass: a.assetClass, assetType: a.assetType, criticality: a.criticality })),
    },
  };
}

export async function classifyCase(caseId: string): Promise<CertInMatch[]> {
  const kase = await loadCase(caseId);
  return classifyIncident((await incidentFacts(kase)).facts);
}

// ---------------------------------------------------------------- drafts

function actionsTaken(kase: LoadedCase): string[] {
  return kase.responseActions.map((a) => {
    const done = a.status === "MANUAL_REQUIRED" ? "requested in the tool's console" : a.status === "ROLLED_BACK" ? "done, since lifted" : "done";
    return `${ACTION_LABEL[a.actionType]}${a.target ? ` ${a.target}` : ""} (${done}, ${a.createdAt.toISOString().slice(0, 16).replace("T", " ")} UTC)`;
  });
}

async function firstSeen(kase: LoadedCase): Promise<Date | null> {
  const [event, entry] = await Promise.all([
    db.securityEvent.findFirst({ where: { caseId: kase.id }, orderBy: { timestamp: "asc" }, select: { timestamp: true } }),
    db.timelineEntry.findFirst({ where: { caseId: kase.id }, orderBy: { occurredAt: "asc" }, select: { occurredAt: true } }),
  ]);
  const times = [event?.timestamp, entry?.occurredAt].filter((d): d is Date => !!d);
  return times.length ? new Date(Math.min(...times.map((d) => d.getTime()))) : null;
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export async function draftCertIn(kase: LoadedCase, book: Rulebook, clockStartAt: Date): Promise<NoticeContent<"CERT_IN">> {
  const { assets } = await incidentFacts(kase);
  const contact = book.obligations.certInContact;
  return parseContent("CERT_IN", {
    reporter: { name: contact.name, organisation: kase.tenant?.name ?? "", designation: "", email: contact.email, phone: contact.phone, address: "" },
    sector: kase.tenant?.industry ?? "",
    occurredAt: iso(await firstSeen(kase)),
    noticedAt: clockStartAt.toISOString(),
    description: [kase.summary || kase.title, kase.rootCauseNarrative].filter(Boolean).join("\n\n").slice(0, 8000),
    symptoms: [...new Set(kase.detections.map((d) => d.title))].slice(0, 40),
    affectedSystems: [
      ...assets.known.map((a) => ({ hostname: a.hostname, ip: a.ipAddress ?? "", os: a.os ?? "", type: (a.assetClass && assetTypeLabel(a.assetClass as AssetClass, a.assetType)) || a.assetType || "", critical: a.criticality === "critical" || a.criticality === "high" })),
      ...assets.unknown.map((h) => ({ hostname: h, ip: "", os: "", type: "", critical: false })),
    ].slice(0, 100),
    indicators: kase.indicators.filter((i) => (i.indicator.maliciousScore ?? 0) >= 0.4 || i.role).map((i) => ({ type: i.indicator.type, value: i.indicator.value })).slice(0, 100),
    techniques: kase.mitreTechniques.map((t) => `${t.techniqueId} ${t.technique.name}`),
    actionsTaken: actionsTaken(kase),
    criticalSystems: assets.known.some((a) => a.criticality === "critical" || a.criticality === "high"),
  });
}

function draftDpdp(kase: LoadedCase, book: Rulebook, input: { principalsAffected: number | null; dataCategories: string[]; occurredAt: Date | null }) {
  const actions = actionsTaken(kase);
  return {
    DPDP_INTIMATION: parseContent("DPDP_INTIMATION", {
      nature: kase.summary || kase.title,
      extent: input.principalsAffected != null ? `About ${input.principalsAffected.toLocaleString("en-IN")} people's data${input.dataCategories.length ? `: ${input.dataCategories.join(", ")}` : ""}` : "",
      principalsAffected: input.principalsAffected,
      dataCategories: input.dataCategories,
      occurredAt: iso(input.occurredAt),
      location: kase.tenant?.name ?? "",
      likelyImpact: "",
    }),
    DPDP_REPORT: parseContent("DPDP_REPORT", {
      facts: [kase.summary || kase.title, kase.rootCauseNarrative].filter(Boolean).join("\n\n"),
      mitigation: actions.join("\n"),
    }),
    DPDP_PRINCIPALS: parseContent("DPDP_PRINCIPALS", {
      description: "",
      mitigation: actions.length ? "We contained the incident and secured the affected systems." : "",
      contact: book.obligations.dpdpContact,
    }),
  };
}

// ---------------------------------------------------------------- opening

async function timeline(caseId: string, action: string, detail: string, actor: string | null | undefined) {
  await db.timelineEntry.create({ data: { caseId, occurredAt: new Date(), actor: actor || "HELIOS", action, detail } });
}

async function clientAdmins(tenantId: string) {
  const users = await db.user.findMany({ where: { tenantId, active: true, role: "CLIENT_ADMIN" as UserRole }, select: { id: true } });
  return users.map((u) => u.id);
}

async function announce(n: RegulatoryNotice, title: string, body: string, opts: { client?: boolean } = {}) {
  const kase = await db.case.findUnique({ where: { id: n.caseId }, select: { domain: true } });
  const staff = await staffFor(["SOC_MANAGER", "INCIDENT_RESPONDER"], kase?.domain);
  const audience = await caseAudience(n.caseId);
  const client = opts.client ? await clientAdmins(n.tenantId) : [];
  await notify([...staff, ...audience, ...client], { kind: "compliance", title, body, caseId: n.caseId, href: `/cases/${n.caseId}#regulatory` });
}

// Opens the CERT-In report on a case: by the rules (the job below) or by an
// analyst, who may pick the types and say when it was really noticed.
export async function openCertIn(caseId: string, opts: { actor?: SessionUser; categories?: string[]; clockStartAt?: Date; reason?: string; matches?: CertInMatch[] } = {}) {
  const kase = await loadCase(caseId);
  if (!kase.tenantId) throw new Error("Only a client's case can be reported");
  const existing = await db.regulatoryNotice.findFirst({ where: { caseId, kind: "CERT_IN" } });
  if (existing) return existing;
  const book = await rulebookFor(kase.tenantId);
  const matches = opts.matches ?? classifyIncident((await incidentFacts(kase)).facts);
  const categories = (opts.categories?.length ? opts.categories : matches.map((m) => m.code)).filter(isCertInCode);
  if (!categories.length) throw new Error("Pick at least one incident type from CERT-In's list");
  const start = opts.clockStartAt ?? kase.createdAt;
  if (start.getTime() > Date.now() + 60_000) throw new Error("The incident can't have been noticed in the future");
  const content = await draftCertIn(kase, book, start);
  const notice = await db.regulatoryNotice
    .create({
      data: {
        tenantId: kase.tenantId,
        caseId,
        kind: "CERT_IN",
        status: "DRAFT",
        clockStartAt: start,
        dueAt: noticeDue("CERT_IN", start, book.obligations.dpdpWithoutDelayHours),
        categories,
        content: content as Prisma.InputJsonValue,
        proposedBy: opts.actor ? "analyst" : "rules",
        reasons: JSON.parse(JSON.stringify({ matches, startReason: opts.reason })) as Prisma.InputJsonValue,
        createdById: opts.actor?.id,
      },
    })
    .catch(async (err) => {
      // Another instance opened it first.
      const again = await db.regulatoryNotice.findFirst({ where: { caseId, kind: "CERT_IN" } });
      if (again) return again;
      throw err;
    });
  await logAction({ actorId: opts.actor?.id, caseId, action: "compliance.notice_opened", detail: { noticeId: notice.id, kind: "CERT_IN", categories, proposedBy: notice.proposedBy, clockStartAt: start, dueAt: notice.dueAt, reason: opts.reason } });
  await timeline(caseId, "compliance.cert_in_opened", `CERT-In report opened (${categories.map((c) => `(${c}) ${certInLabel(c)}`).join("; ")}). Due by ${notice.dueAt!.toISOString().slice(0, 16).replace("T", " ")} UTC, 6 hours from when the incident was noticed.`, opts.actor?.name ?? "HELIOS");
  await announce(notice, `CERT-In report due in 6 hours: ${kase.title}`, `${kase.tenant?.name ?? "Client"} · due ${notice.dueAt!.toISOString().slice(11, 16)} UTC`, { client: true });
  return notice;
}

// The DPDP workflow: the three notices, from when the client became aware
// that personal data was breached.
export async function openDpdp(caseId: string, actor: SessionUser, input: { awareAt: Date; principalsAffected: number | null; dataCategories: string[] }) {
  const kase = await loadCase(caseId);
  if (!kase.tenantId) throw new Error("Only a client's case can be reported");
  if (input.awareAt.getTime() > Date.now() + 60_000) throw new Error("Awareness can't be in the future");
  const book = await rulebookFor(kase.tenantId);
  const drafts = draftDpdp(kase, book, { ...input, occurredAt: await firstSeen(kase) });
  const created: RegulatoryNotice[] = [];
  for (const kind of ["DPDP_INTIMATION", "DPDP_REPORT", "DPDP_PRINCIPALS"] as const) {
    if (await db.regulatoryNotice.findFirst({ where: { caseId, kind } })) continue;
    created.push(
      await db.regulatoryNotice.create({
        data: {
          tenantId: kase.tenantId,
          caseId,
          kind,
          clockStartAt: input.awareAt,
          dueAt: noticeDue(kind, input.awareAt, book.obligations.dpdpWithoutDelayHours),
          content: drafts[kind] as Prisma.InputJsonValue,
          proposedBy: "analyst",
          createdById: actor.id,
        },
      }),
    );
  }
  if (!created.length) throw new Error("The DPDP notices for this case are already open");
  await logAction({ actorId: actor.id, caseId, action: "compliance.dpdp_opened", detail: { notices: created.map((n) => ({ id: n.id, kind: n.kind, dueAt: n.dueAt })), awareAt: input.awareAt, principalsAffected: input.principalsAffected, dataCategories: input.dataCategories } });
  await timeline(caseId, "compliance.dpdp_opened", `Personal data breach recorded: the Data Protection Board and the people affected are to be told without delay, and the Board's detailed report is due within ${DPDP_REPORT_HOURS} hours.`, actor.name ?? actor.email);
  await announce(created[0], `Personal data breach: Board and people affected to be told — ${kase.title}`, `${kase.tenant?.name ?? "Client"} · detailed report due in ${DPDP_REPORT_HOURS} h`, { client: true });
  return created;
}

// ---------------------------------------------------------------- the workflow

async function noticeFor(id: string) {
  return db.regulatoryNotice.findUniqueOrThrow({ where: { id }, include: { case: { select: { id: true, title: true, tenantId: true } }, tenant: { select: { name: true } } } });
}

function editable(n: RegulatoryNotice) {
  if (n.status === "SUBMITTED") throw new Error("This notice has been filed; add an update instead");
  if (n.status === "NOT_REQUIRED") throw new Error("This notice was marked not required; reopen it first");
}

export async function saveNotice(id: string, actor: SessionUser, input: { content: unknown; categories?: string[] }) {
  const n = await noticeFor(id);
  editable(n);
  const content = parseContent(n.kind, input.content);
  const categories = n.kind === "CERT_IN" ? (input.categories ?? n.categories).filter(isCertInCode) : [];
  if (n.kind === "CERT_IN" && !categories.length) throw new Error("Pick at least one incident type from CERT-In's list");
  // An approval covers the text that was approved, not later edits.
  const reset = n.status !== "DRAFT";
  await db.regulatoryNotice.update({
    where: { id },
    data: { content: content as Prisma.InputJsonValue, categories, ...(reset ? { status: "DRAFT", approvedAt: null, approvedById: null, approvedByName: null, approvedVia: null } : {}) },
  });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.notice_edited", detail: { noticeId: id, kind: n.kind, approvalWithdrawn: reset } });
}

export async function setClockStart(id: string, actor: SessionUser, at: Date, reason: string) {
  const n = await noticeFor(id);
  editable(n);
  if (!reason.trim()) throw new Error("Say why the clock starts at a different time");
  if (at.getTime() > Date.now() + 60_000) throw new Error("That's in the future");
  const book = await rulebookFor(n.tenantId);
  const dueAt = noticeDue(n.kind, at, book.obligations.dpdpWithoutDelayHours);
  await db.regulatoryNotice.update({ where: { id }, data: { clockStartAt: at, dueAt, remindedStage: 0 } });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.clock_changed", detail: { noticeId: id, from: n.clockStartAt, to: at, dueAt, reason } });
}

// The Board may allow more than 72 hours for the detailed report.
export async function extendDeadline(id: string, actor: SessionUser, until: Date, reason: string) {
  const n = await noticeFor(id);
  editable(n);
  if (n.kind !== "DPDP_REPORT") throw new Error("Only the Board's detailed report can be extended");
  if (!reason.trim()) throw new Error("Record the Board's permission (its reference or message)");
  if (n.dueAt && until <= n.dueAt) throw new Error("An extension has to be later than the current deadline");
  await db.regulatoryNotice.update({ where: { id }, data: { dueAt: until, remindedStage: 0, reasons: { ...((n.reasons ?? {}) as object), extension: { until: until.toISOString(), reason, by: actor.name ?? actor.email } } as Prisma.InputJsonValue } });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.deadline_extended", detail: { noticeId: id, from: n.dueAt, to: until, reason } });
}

export async function requestApproval(id: string, actor: SessionUser) {
  const n = await noticeFor(id);
  if (n.status !== "DRAFT") throw new Error("Only a draft can be sent for approval");
  const missing = missingFields(n.kind, n.content as Record<string, unknown>);
  if (missing.length) throw new Error(`Fill in ${missing.join(", ")} first`);
  await db.regulatoryNotice.update({ where: { id }, data: { status: "AWAITING_APPROVAL" } });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.approval_requested", detail: { noticeId: id, kind: n.kind } });
  await notify(await clientAdmins(n.tenantId), { kind: "compliance", title: `Approve before it's filed: ${NOTICE_LABEL[n.kind]}`, body: `${n.case.title}${n.dueAt ? ` · due ${n.dueAt.toISOString().slice(0, 16).replace("T", " ")} UTC` : ""}`, caseId: n.caseId, href: `/cases/${n.caseId}#regulatory`, actorName: actor.name });
}

// A client admin approves in the app; staff record an approval the client
// gave by phone or email, naming who gave it.
export async function approveNotice(id: string, actor: SessionUser, onBehalf?: { name: string; via: string }) {
  const n = await noticeFor(id);
  // The client approves what the SOC sent it; staff may record an approval
  // the client gave on a draft they went through together.
  const approvable = actor.isClient ? n.status === "AWAITING_APPROVAL" : n.status === "AWAITING_APPROVAL" || n.status === "DRAFT";
  if (!approvable) throw new Error(n.status === "APPROVED" ? "Already approved" : n.status === "DRAFT" ? "Your SOC hasn't sent this for approval yet" : "This notice can't be approved now");
  const missing = missingFields(n.kind, n.content as Record<string, unknown>);
  if (missing.length) throw new Error(`Fill in ${missing.join(", ")} first`);
  if (actor.isClient) {
    if (actor.tenantId !== n.tenantId) throw new Error("Not found");
  } else if (!onBehalf?.name.trim() || !onBehalf.via.trim()) {
    throw new Error("Name the client's approver and how they approved");
  }
  const name = actor.isClient ? (actor.name ?? actor.email) : onBehalf!.name.trim();
  const via = actor.isClient ? "app" : onBehalf!.via.trim();
  await db.regulatoryNotice.update({ where: { id }, data: { status: "APPROVED", approvedAt: new Date(), approvedById: actor.id, approvedByName: name, approvedVia: via } });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.notice_approved", detail: { noticeId: id, kind: n.kind, approvedBy: name, via, recordedBy: actor.isClient ? null : actor.email } });
  await timeline(n.caseId, "compliance.notice_approved", `${NOTICE_LABEL[n.kind]} approved by ${name}${via === "app" ? "" : ` (${via}, recorded by ${actor.name ?? actor.email})`}.`, name);
  await announce(n, `Approved, ready to file: ${NOTICE_LABEL[n.kind]}`, n.case.title);
}

export interface SubmitInput {
  via: SubmitChannel;
  reference?: string;
  recipientsCount?: number;
  note?: string;
}

// Files an approved notice: emails CERT-In from HELIOS with the report
// attached (the client's point of contact copied), or records a filing made
// elsewhere.
export async function submitNotice(id: string, actor: SessionUser, input: SubmitInput) {
  const n = await noticeFor(id);
  if (n.status !== "APPROVED") throw new Error("A notice is filed only once the client has approved it");
  if (input.via === "email" && n.kind !== "CERT_IN") throw new Error("Only the CERT-In report is emailed from here; file Board notices on the Board's own platform and record it");
  if (input.via === "email" && actor.isClient) throw new Error("Record your own filing instead");
  if (n.kind === "DPDP_PRINCIPALS" && !(input.recipientsCount && input.recipientsCount > 0)) throw new Error("Say how many people were told");
  if (input.via !== "email" && !input.reference?.trim() && n.kind !== "DPDP_PRINCIPALS") throw new Error("Record the acknowledgement or reference you were given (or how it was filed)");

  let messageId: string | null = null;
  if (input.via === "email") {
    const content = parseContent("CERT_IN", n.content);
    const book = await rulebookFor(n.tenantId);
    const pdf = await renderNoticePdf(id);
    const cc = [...new Set([content.reporter.email, book.obligations.certInContact.email, ...book.obligations.reportRecipients].filter((e) => e && /@/.test(e)))];
    const result = await sendMail({
      to: [CERT_IN_CONTACT.email],
      cc,
      replyTo: content.reporter.email || undefined,
      subject: `Cyber security incident report${n.sequence > 1 ? ` (update ${n.sequence - 1})` : ""}: ${content.reporter.organisation || n.tenant.name} — ${n.categories.map((c) => certInLabel(c)).join("; ").slice(0, 120)}`,
      text: certInEmail(content, n.categories, { tenantName: n.tenant.name, caseRef: n.caseId, sequence: n.sequence }),
      attachments: [{ filename: `cert-in-report-${n.caseId}${n.sequence > 1 ? `-update-${n.sequence - 1}` : ""}.pdf`, content: pdf, contentType: "application/pdf" }],
    });
    if (!result.accepted.some((a) => a.toLowerCase() === CERT_IN_CONTACT.email)) throw new Error(`The mail server didn't accept the message for ${CERT_IN_CONTACT.email}`);
    messageId = result.messageId;
  }

  const now = new Date();
  await db.regulatoryNotice.update({
    where: { id },
    data: { status: "SUBMITTED", submittedAt: now, submittedById: actor.id, submittedVia: input.via, reference: input.reference?.trim() || null, recipientsCount: input.recipientsCount ?? null, messageId },
  });
  const late = n.dueAt && now > n.dueAt;
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.notice_submitted", detail: { noticeId: id, kind: n.kind, via: input.via, reference: input.reference, recipientsCount: input.recipientsCount, messageId, dueAt: n.dueAt, late: !!late, note: input.note } });
  await timeline(n.caseId, "compliance.notice_submitted", `${NOTICE_LABEL[n.kind]} filed (${input.via}${input.reference ? `, reference ${input.reference}` : ""}${input.recipientsCount ? `, ${input.recipientsCount} people told` : ""})${late ? " after its deadline" : ""}.`, actor.name ?? actor.email);
  await announce(n, `Filed: ${NOTICE_LABEL[n.kind]}`, n.case.title, { client: true });
}

export async function markNotRequired(id: string, actor: SessionUser | null, reason: string) {
  const n = await noticeFor(id);
  if (n.status === "SUBMITTED") throw new Error("A filed notice stays on record");
  if (!reason.trim()) throw new Error("Say why it isn't needed");
  await db.regulatoryNotice.update({ where: { id }, data: { status: "NOT_REQUIRED", notRequiredReason: reason.trim() } });
  await logAction({ actorId: actor?.id, caseId: n.caseId, action: "compliance.notice_not_required", detail: { noticeId: id, kind: n.kind, reason } });
  await timeline(n.caseId, "compliance.notice_not_required", `${NOTICE_LABEL[n.kind]} not required: ${reason.trim()}`, actor?.name ?? "HELIOS");
}

export async function reopenNotice(id: string, actor: SessionUser) {
  const n = await noticeFor(id);
  if (n.status !== "NOT_REQUIRED") throw new Error("Only a notice marked not required can be reopened");
  await db.regulatoryNotice.update({ where: { id }, data: { status: "DRAFT", notRequiredReason: null, approvedAt: null, approvedById: null, approvedByName: null, approvedVia: null } });
  await logAction({ actorId: actor.id, caseId: n.caseId, action: "compliance.notice_reopened", detail: { noticeId: id, kind: n.kind } });
}

// A follow-up to a filed CERT-In report, with what's been learned since.
export async function addUpdate(caseId: string, actor: SessionUser) {
  const last = await db.regulatoryNotice.findFirst({ where: { caseId, kind: "CERT_IN" }, orderBy: { sequence: "desc" } });
  if (!last || last.status !== "SUBMITTED") throw new Error("File the report before sending an update");
  const kase = await loadCase(caseId);
  const book = await rulebookFor(last.tenantId);
  const prior = parseContent("CERT_IN", last.content);
  const fresh = await draftCertIn(kase, book, last.clockStartAt);
  const content = { ...fresh, reporter: prior.reporter, sector: prior.sector, reportedTo: prior.reportedTo, additionalInfo: last.reference ? `Update to the report filed ${last.submittedAt!.toISOString().slice(0, 16).replace("T", " ")} UTC (reference ${last.reference}).` : `Update to the report filed ${last.submittedAt!.toISOString().slice(0, 16).replace("T", " ")} UTC.` };
  const notice = await db.regulatoryNotice.create({
    data: { tenantId: last.tenantId, caseId, kind: "CERT_IN", sequence: last.sequence + 1, clockStartAt: last.clockStartAt, dueAt: null, categories: last.categories, content: content as Prisma.InputJsonValue, proposedBy: "analyst", createdById: actor.id },
  });
  await logAction({ actorId: actor.id, caseId, action: "compliance.update_opened", detail: { noticeId: notice.id, sequence: notice.sequence } });
  return notice;
}

// ---------------------------------------------------------------- PDF

export async function renderNoticePdf(id: string): Promise<Buffer> {
  const { NoticePdf } = await import("@/lib/pdf/notice");
  const [n, company] = await Promise.all([
    db.regulatoryNotice.findUniqueOrThrow({ where: { id }, include: { case: { select: { id: true, title: true } }, tenant: { select: { name: true } } } }),
    getSetting("company.profile"),
  ]);
  const principals = n.kind === "DPDP_REPORT" ? await db.regulatoryNotice.findFirst({ where: { caseId: n.caseId, kind: "DPDP_PRINCIPALS" } }) : null;
  return renderPdf(createElement(NoticePdf, { notice: n, company, principals }));
}

// ---------------------------------------------------------------- the job

let lastSweep = 0;

// Every minute: open CERT-In reports for cases that now qualify, close out
// notices on cases found to be false positives, and remind people as each
// deadline gets near and when it passes.
export async function checkRegulatoryClocks(now = new Date()) {
  const since = new Date(Math.max(now.getTime() - 24 * HOUR, lastSweep - 60_000));
  lastSweep = now.getTime();
  let opened = 0;
  let closed = 0;
  let reminded = 0;

  // 1. New and changed cases of clients CERT-In reporting applies to.
  const tenants = await db.tenant.findMany({ where: { status: { not: "SUSPENDED" } }, select: { id: true } });
  for (const t of tenants) {
    const book = await rulebookFor(t.id);
    if (!book.obligations.regulatedEntity) continue;
    const cases = await db.case.findMany({
      where: {
        tenantId: t.id,
        updatedAt: { gte: since },
        createdAt: { gte: new Date(now.getTime() - 7 * 24 * HOUR) },
        status: { not: "FALSE_POSITIVE" },
        OR: [{ disposition: null }, { disposition: "TRUE_POSITIVE" }],
        notices: { none: { kind: "CERT_IN" } },
      },
      select: { id: true, severity: true },
      take: 500,
    });
    for (const c of cases) {
      if (!atLeast(c.severity, book.obligations.certInMinSeverity)) continue;
      const matches = await classifyCase(c.id);
      if (!matches.length) continue;
      await openCertIn(c.id, { matches });
      opened++;
    }
  }

  // 2. Notices whose case turned out not to be an incident.
  const stale = await db.regulatoryNotice.findMany({
    where: { status: { in: OPEN }, case: { OR: [{ status: "FALSE_POSITIVE" }, { disposition: { in: ["FALSE_POSITIVE", "BENIGN_TRUE_POSITIVE"] } }] } },
    select: { id: true, case: { select: { disposition: true } } },
  });
  for (const s of stale) {
    await markNotRequired(s.id, null, s.case.disposition === "BENIGN_TRUE_POSITIVE" ? "The case was closed as expected or authorised activity" : "The case was closed as a false positive");
    closed++;
  }

  // 3. Reminders, once per stage, claimed atomically so two instances
  // don't both send them.
  const open = await db.regulatoryNotice.findMany({ where: { status: { in: OPEN }, dueAt: { not: null } }, include: { case: { select: { title: true } }, tenant: { select: { name: true } } } });
  for (const n of open) {
    const stage = reminderStage(n, now);
    if (stage <= n.remindedStage || stage < 2) continue;
    const claimed = await db.regulatoryNotice.updateMany({ where: { id: n.id, remindedStage: { lt: stage } }, data: { remindedStage: stage } });
    if (!claimed.count) continue;
    const left = n.dueAt!.getTime() - now.getTime();
    const when = left < 0 ? `overdue by ${Math.round(-left / 60_000)} min` : `due in ${Math.round(left / 60_000)} min`;
    await announce(n, `${stage === 4 ? "Overdue" : "Due soon"}: ${NOTICE_LABEL[n.kind]} — ${n.case.title}`, `${n.tenant.name} · ${when} · ${n.status === "AWAITING_APPROVAL" ? "waiting for the client's approval" : n.status === "APPROVED" ? "approved, not yet filed" : "still a draft"}`, { client: n.status === "AWAITING_APPROVAL" || stage === 4 });
    if (stage === 4) await logAction({ caseId: n.caseId, action: "compliance.deadline_missed", detail: { noticeId: n.id, kind: n.kind, dueAt: n.dueAt, status: n.status } });
    reminded++;
  }
  return { opened, closed, reminded };
}
