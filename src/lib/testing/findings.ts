import { createHash } from "node:crypto";

// What a security test found, whichever tool found it. Findings stay on
// the test as remediation items: open until fixed (a re-test confirms it)
// or accepted as a risk with a reason.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type FindingSeverity = (typeof SEVERITIES)[number];

export interface TestFinding {
  id: string;
  title: string;
  severity: FindingSeverity;
  target: string;
  port: number | null;
  service: string | null;
  evidence: string;
  remediation: string;
  references: string[];
  source: string;
  status: "open" | "fixed" | "accepted";
  statusNote: string | null;
  firstSeen: string;
  lastSeen: string;
}

export type NewFinding = Omit<TestFinding, "id" | "status" | "statusNote" | "firstSeen" | "lastSeen">;

export const SEVERITY_RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function findingId(f: Pick<NewFinding, "source" | "target" | "port" | "title">): string {
  return createHash("sha256").update([f.source, f.target.toLowerCase(), f.port ?? "", f.title].join("|")).digest("hex").slice(0, 16);
}

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function finding(f: NewFinding, now: Date): TestFinding {
  const iso = now.toISOString();
  return {
    ...f,
    title: clip(f.title.trim(), 300),
    evidence: clip(f.evidence.trim(), 2000),
    remediation: clip(f.remediation.trim(), 2000),
    references: [...new Set(f.references.map((r) => r.trim()).filter(Boolean))].slice(0, 20),
    id: findingId(f),
    status: "open",
    statusNote: null,
    firstSeen: iso,
    lastSeen: iso,
  };
}

// A new run's findings merged into what the test already holds:
// - seen again: keeps its status (an accepted risk stays accepted), lastSeen moves;
// - new: added as open;
// - not seen again where this run actually looked (same tool, a target it
//   checked): fixed, the re-test confirms it. A target the run skipped
//   (its proof was gone, say) proves nothing either way.
export function mergeFindings(existing: TestFinding[], fresh: TestFinding[], covered: (f: TestFinding) => boolean, now: Date): TestFinding[] {
  const byId = new Map(existing.map((f) => [f.id, f]));
  const out: TestFinding[] = [];
  const seen = new Set<string>();
  for (const f of fresh) {
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    const old = byId.get(f.id);
    out.push(old ? { ...f, status: old.status === "fixed" ? "open" : old.status, statusNote: old.status === "fixed" ? "Found again in a later run" : old.statusNote, firstSeen: old.firstSeen, lastSeen: now.toISOString() } : f);
  }
  for (const old of existing) {
    if (seen.has(old.id)) continue;
    if (covered(old) && old.status === "open") out.push({ ...old, status: "fixed", statusNote: `Not found again on ${now.toISOString().slice(0, 10)}` });
    else out.push(old);
  }
  return out.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.target.localeCompare(b.target) || (a.port ?? 0) - (b.port ?? 0));
}

export function severityCounts(fs: TestFinding[], status: TestFinding["status"] | "all" = "open") {
  const out = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<FindingSeverity, number>;
  for (const f of fs) if (status === "all" || f.status === status) out[f.severity]++;
  return out;
}
