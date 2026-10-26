import type { NoticeKind } from "@prisma/client";
import { z } from "zod";

import { CERT_IN_HOURS, certInLabel } from "@/lib/compliance/cert-in";
import { DPDP_REPORT_HOURS } from "@/lib/compliance/dpdp";

// Regulatory notices of every kind: names, deadlines, what each still
// needs before it can go out, and the clock. Pure and client-safe.

export const NOTICE_LABEL: Record<NoticeKind, string> = {
  CERT_IN: "CERT-In incident report",
  DPDP_INTIMATION: "Intimation to the Data Protection Board",
  DPDP_REPORT: "Detailed report to the Data Protection Board",
  DPDP_PRINCIPALS: "Notice to affected Data Principals",
};

export const NOTICE_RECIPIENT: Record<NoticeKind, string> = {
  CERT_IN: "CERT-In",
  DPDP_INTIMATION: "Data Protection Board",
  DPDP_REPORT: "Data Protection Board",
  DPDP_PRINCIPALS: "the people affected",
};

// What the deadline is, in words, for a kind.
export const NOTICE_DEADLINE: Record<NoticeKind, string> = {
  CERT_IN: `within ${CERT_IN_HOURS} hours of noticing the incident`,
  DPDP_INTIMATION: "without delay",
  DPDP_REPORT: `within ${DPDP_REPORT_HOURS} hours of becoming aware (or longer, if the Board allows)`,
  DPDP_PRINCIPALS: "without delay",
};

// When each notice is due, from the time the clock started. "Without
// delay" has no number in law: the client's own target stands in for it.
export function noticeDue(kind: NoticeKind, start: Date, withoutDelayHours: number): Date {
  const hours = kind === "CERT_IN" ? CERT_IN_HOURS : kind === "DPDP_REPORT" ? DPDP_REPORT_HOURS : withoutDelayHours;
  return new Date(start.getTime() + hours * 3_600_000);
}

// What's still blank that the notice needs before it goes out.
export function missingFields(kind: NoticeKind, content: Record<string, unknown>): string[] {
  const blank = (v: unknown) => v === undefined || v === null || (typeof v === "string" && !v.trim()) || (Array.isArray(v) && v.length === 0);
  const need: Record<NoticeKind, Array<[string, string]>> = {
    CERT_IN: [["description", "description"]],
    DPDP_INTIMATION: [["nature", "nature of the breach"], ["extent", "extent"], ["likelyImpact", "likely impact"]],
    DPDP_REPORT: [["facts", "facts and circumstances"], ["mitigation", "mitigation measures"], ["remediation", "measures to prevent it happening again"]],
    DPDP_PRINCIPALS: [["description", "description of the breach"], ["consequences", "likely consequences"], ["safetySteps", "steps people can take"]],
  };
  const out = need[kind].filter(([k]) => blank(content[k])).map(([, label]) => label);
  if (kind === "CERT_IN") {
    const reporter = (content.reporter ?? {}) as Record<string, unknown>;
    if (blank(reporter.name) || (blank(reporter.email) && blank(reporter.phone))) out.push("the client's point of contact");
  }
  if (kind === "DPDP_PRINCIPALS") {
    const contact = (content.contact ?? {}) as Record<string, unknown>;
    if (blank(contact.email) && blank(contact.phone)) out.push("a contact for affected people");
  }
  return out;
}

// ---------------------------------------------------------------- the clock

export type ClockState = "running" | "due_soon" | "overdue" | "met" | "late" | "closed";

export interface Clock {
  state: ClockState;
  // Until due (negative once past), or how early/late it was filed.
  marginMs: number | null;
  elapsedMs: number;
}

// due_soon: the last sixth of the window (an hour of CERT-In's six).
export function clockOf(n: { clockStartAt: Date; dueAt: Date | null; submittedAt: Date | null; status: string }, now = new Date()): Clock {
  const elapsedMs = (n.submittedAt ?? now).getTime() - n.clockStartAt.getTime();
  if (n.status === "NOT_REQUIRED") return { state: "closed", marginMs: null, elapsedMs };
  if (!n.dueAt) return { state: n.submittedAt ? "met" : "running", marginMs: null, elapsedMs };
  if (n.submittedAt) {
    const margin = n.dueAt.getTime() - n.submittedAt.getTime();
    return { state: margin >= 0 ? "met" : "late", marginMs: margin, elapsedMs };
  }
  const margin = n.dueAt.getTime() - now.getTime();
  const window = n.dueAt.getTime() - n.clockStartAt.getTime();
  return { state: margin < 0 ? "overdue" : margin <= window / 6 ? "due_soon" : "running", marginMs: margin, elapsedMs };
}

// Reminder stages: 1 opened, 2 half the time gone, 3 due soon, 4 overdue.
export function reminderStage(n: { clockStartAt: Date; dueAt: Date | null }, now = new Date()): number {
  if (!n.dueAt) return 1;
  const window = n.dueAt.getTime() - n.clockStartAt.getTime();
  const gone = now.getTime() - n.clockStartAt.getTime();
  if (gone > window) return 4;
  if (gone >= (window * 5) / 6) return 3;
  if (gone >= window / 2) return 2;
  return 1;
}

export function formatSpan(ms: number) {
  const m = Math.round(Math.abs(ms) / 60_000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h} h ${m % 60} min` : `${Math.round(h / 24)} days`;
}

// ---------------------------------------------------------------- content

const text = (max: number) => z.string().trim().max(max).default("");
const contact = z.object({ name: text(120), email: text(200), phone: text(40) }).default({ name: "", email: "", phone: "" });

export const certInContentSchema = z.object({
  reporter: z
    .object({ name: text(120), organisation: text(200), designation: text(120), email: text(200), phone: text(40), address: text(400) })
    .default({ name: "", organisation: "", designation: "", email: "", phone: "", address: "" }),
  sector: text(120),
  occurredAt: z.string().max(40).nullable().default(null),
  noticedAt: z.string().max(40).default(""),
  description: text(8000),
  symptoms: z.array(z.string().trim().min(1).max(400)).max(40).default([]),
  affectedSystems: z
    .array(z.object({ hostname: text(200), ip: text(64), os: text(120), type: text(120), critical: z.boolean().default(false) }))
    .max(100)
    .default([]),
  indicators: z.array(z.object({ type: text(40), value: z.string().trim().min(1).max(500) })).max(100).default([]),
  techniques: z.array(z.string().trim().max(200)).max(60).default([]),
  actionsTaken: z.array(z.string().trim().min(1).max(400)).max(40).default([]),
  criticalSystems: z.boolean().default(false),
  reportedTo: text(400),
  additionalInfo: text(4000),
});

export const dpdpIntimationSchema = z.object({
  nature: text(4000),
  extent: text(2000),
  principalsAffected: z.number().int().min(0).max(2_000_000_000).nullable().default(null),
  dataCategories: z.array(z.string().trim().min(1).max(120)).max(40).default([]),
  occurredAt: z.string().max(40).nullable().default(null),
  location: text(1000),
  likelyImpact: text(4000),
});

export const dpdpReportSchema = z.object({
  facts: text(8000),
  mitigation: text(4000),
  personFindings: text(4000),
  remediation: text(4000),
  principalsReport: text(4000),
});

export const dpdpPrincipalsSchema = z.object({
  description: text(4000),
  consequences: text(4000),
  mitigation: text(4000),
  safetySteps: text(4000),
  contact,
});

export const CONTENT_SCHEMA = {
  CERT_IN: certInContentSchema,
  DPDP_INTIMATION: dpdpIntimationSchema,
  DPDP_REPORT: dpdpReportSchema,
  DPDP_PRINCIPALS: dpdpPrincipalsSchema,
} as const satisfies Record<NoticeKind, z.ZodType>;

export type NoticeContent<K extends NoticeKind> = z.infer<(typeof CONTENT_SCHEMA)[K]>;

export function parseContent<K extends NoticeKind>(kind: K, content: unknown): NoticeContent<K> {
  return CONTENT_SCHEMA[kind].parse(content ?? {}) as NoticeContent<K>;
}

export const SUBMIT_CHANNELS = { email: "Email from HELIOS", portal: "Regulator's portal", phone: "Phone", client: "Sent by the client", other: "Other" } as const;
export type SubmitChannel = keyof typeof SUBMIT_CHANNELS;

// The email body that goes with the report (the PDF is attached).
export function certInEmail(r: NoticeContent<"CERT_IN">, categories: string[], meta: { tenantName: string; caseRef: string; sequence: number }) {
  const lines = [
    `Cyber security incident report${meta.sequence > 1 ? ` (update ${meta.sequence - 1})` : ""} under CERT-In's directions of 28 April 2022.`,
    "",
    `Reporting entity: ${r.reporter.organisation || meta.tenantName}`,
    `Point of contact: ${[r.reporter.name, r.reporter.designation].filter(Boolean).join(", ")} · ${[r.reporter.email, r.reporter.phone].filter(Boolean).join(" · ")}`,
    r.sector ? `Sector: ${r.sector}` : null,
    `Incident type (Annexure I): ${categories.map((c) => `(${c}) ${certInLabel(c)}`).join("; ")}`,
    r.occurredAt ? `Occurred: ${r.occurredAt}` : null,
    `Noticed: ${r.noticedAt}`,
    "",
    "Description:",
    r.description,
    r.symptoms.length > 0 && ["", "Symptoms observed:", ...r.symptoms.map((s) => `- ${s}`)].join("\n"),
    r.affectedSystems.length > 0 && ["", "Affected systems:", ...r.affectedSystems.map((s) => `- ${[s.hostname, s.ip, s.os, s.type].filter(Boolean).join(" · ")}${s.critical ? " (critical)" : ""}`)].join("\n"),
    r.actionsTaken.length > 0 && ["", "Actions taken:", ...r.actionsTaken.map((s) => `- ${s}`)].join("\n"),
    "",
    `Reference: ${meta.caseRef}. The full report is attached.`,
  ];
  return lines.filter((l): l is string => typeof l === "string").join("\n");
}
