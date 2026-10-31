import { z } from "zod";
import type { CaseSeverity, CaseSource } from "@prisma/client";

// Runbooks, pure: what a runbook holds, which cases it fits, and how far a
// case has got through it. Client-safe.

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const RANK: Record<CaseSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export const CASE_SOURCES: Record<CaseSource, string> = {
  SIEM_ALERT: "Detections (SIEM)",
  EMAIL_ANALYSIS: "Email and file forensics",
  SOC_INVESTIGATION: "Log investigations",
  AGENT_GOVERNANCE: "AI agent governance",
};

export const stepSchema = z.object({
  id: z.string().trim().min(1).max(40),
  title: z.string().trim().min(1, "Every step needs a title").max(200),
  detail: z.string().trim().max(2000).default(""),
  required: z.boolean().default(false),
});
export type RunbookStep = z.infer<typeof stepSchema>;

export const matchSchema = z
  .object({
    sources: z.array(z.enum(Object.keys(CASE_SOURCES) as [CaseSource, ...CaseSource[]])).max(4).default([]),
    // An ATT&CK technique also matches its sub-techniques.
    techniques: z.array(z.string().trim().toUpperCase().regex(/^T\d{4}(\.\d{3})?$/, "Techniques look like T1566 or T1566.001")).max(40).default([]),
    // Words in the case title; a keyword matches words that start with it
    // ("phish" matches "phishing").
    keywords: z.array(z.string().trim().toLowerCase().min(2).max(60)).max(40).default([]),
    minSeverity: z.enum(SEVERITIES).nullable().default(null),
  })
  .refine((m) => m.techniques.length + m.keywords.length > 0, { message: "Say which cases it's for: at least one ATT&CK technique or title keyword" });
export type RunbookMatch = z.infer<typeof matchSchema>;

export const runbookSchema = z.object({
  title: z.string().trim().min(3).max(160),
  description: z.string().trim().max(4000).default(""),
  match: matchSchema,
  steps: z
    .array(stepSchema)
    .min(1, "A runbook needs at least one step")
    .max(60)
    .refine((s) => new Set(s.map((x) => x.id)).size === s.length, { message: "Step ids must be unique" }),
});
export type RunbookInput = z.infer<typeof runbookSchema>;

export interface CaseFacts {
  source: CaseSource;
  severity: CaseSeverity;
  title: string;
  techniques: string[];
}

const wordIn = (text: string, word: string) => new RegExp(`(^|[^a-z0-9])${word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(text);

// How well a runbook fits a case; null when it doesn't. Source and severity
// narrow; at least one technique or keyword has to hit.
export function matchScore(m: RunbookMatch, c: CaseFacts): number | null {
  if (m.sources.length && !m.sources.includes(c.source)) return null;
  if (m.minSeverity && RANK[c.severity] < RANK[m.minSeverity]) return null;
  const techniques = m.techniques.filter((t) => c.techniques.some((x) => x === t || x.startsWith(`${t}.`))).length;
  const keywords = m.keywords.filter((k) => wordIn(c.title, k)).length;
  if (techniques + keywords === 0) return null;
  return techniques * 2 + keywords + (m.sources.length ? 0.5 : 0);
}

export interface StepState {
  by: string;
  byId: string;
  at: string;
  note?: string;
  skipped?: boolean;
}
export type Progress = Record<string, StepState>;

export function parseProgress(value: unknown): Progress {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Progress) : {};
}

export function parseSteps(value: unknown): RunbookStep[] {
  const parsed = z.array(stepSchema).safeParse(value);
  return parsed.success ? parsed.data : [];
}

export function progressOf(steps: RunbookStep[], progress: Progress) {
  const done = steps.filter((s) => progress[s.id]).length;
  const requiredOpen = steps.filter((s) => s.required && !progress[s.id]);
  return { done, total: steps.length, requiredOpen, complete: done === steps.length };
}
