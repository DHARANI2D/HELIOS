import type { CaseSource, CaseStatus } from "@prisma/client";

// Presentation constants for cases — safe to import from client components
// (no database access), unlike lib/cases/service.

export const CASE_STATUSES: CaseStatus[] = [
  "OPEN",
  "TRIAGING",
  "INVESTIGATING",
  "AWAITING_APPROVAL",
  "CONTAINED",
  "RESOLVED",
  "FALSE_POSITIVE",
];

export const CLOSED_STATUSES: CaseStatus[] = ["RESOLVED", "FALSE_POSITIVE"];

export const CASE_STATUS_LABEL: Record<CaseStatus, string> = {
  OPEN: "Open",
  TRIAGING: "Triaging",
  INVESTIGATING: "Investigating",
  AWAITING_APPROVAL: "Awaiting approval",
  CONTAINED: "Contained",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False positive",
};

export const CASE_SOURCES: CaseSource[] = ["SIEM_ALERT", "SOC_INVESTIGATION", "EMAIL_ANALYSIS", "AGENT_GOVERNANCE"];

export const CASE_SOURCE_LABEL: Record<CaseSource, string> = {
  SIEM_ALERT: "SIEM alert",
  SOC_INVESTIGATION: "Investigation",
  EMAIL_ANALYSIS: "Email forensics",
  AGENT_GOVERNANCE: "Agent governance",
};

// The module page each source's cases originate from.
export const CASE_SOURCE_HREF: Record<CaseSource, string> = {
  SIEM_ALERT: "/cases",
  SOC_INVESTIGATION: "/investigations",
  EMAIL_ANALYSIS: "/forensics",
  AGENT_GOVERNANCE: "/governance",
};
