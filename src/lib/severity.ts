import type { CaseSeverity } from "@prisma/client";

// Central severity -> presentation mapping, shared by every feature area
// (Cases & Alerts, Investigations, Forensics, Governance) so severity never
// gets a bespoke color scheme per module.
export const SEVERITY_ORDER: CaseSeverity[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
];

export const SEVERITY_LABEL: Record<CaseSeverity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  INFO: "Info",
};

// Status palette per the dataviz skill's validated defaults — fixed, never
// themed per-module. INFO isn't a status role, so it uses muted ink instead.
export const SEVERITY_CHART_COLOR: Record<
  CaseSeverity,
  { light: string; dark: string }
> = {
  CRITICAL: { light: "#d03b3b", dark: "#d03b3b" },
  HIGH: { light: "#ec835a", dark: "#ec835a" },
  MEDIUM: { light: "#fab219", dark: "#fab219" },
  LOW: { light: "#0ca30c", dark: "#0ca30c" },
  INFO: { light: "#898781", dark: "#898781" },
};

export const SEVERITY_BADGE_VARIANT: Record<
  CaseSeverity,
  "destructive" | "warning" | "secondary" | "outline"
> = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "warning",
  LOW: "secondary",
  INFO: "outline",
};
