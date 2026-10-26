import type { CaseSeverity } from "@prisma/client";

import type { ScoredDetection, UnifiedEvent } from "@/lib/siem/types";

// Per-client tuning of detections: switch a detector or rule off for one
// client, leave out events that are known to be fine there (a build server,
// a backup tool), or set the severity it raises. Each tuning carries its
// reason and an optional expiry, and counts what it held back, so stale
// tuning shows up. Pure.

export const TUNING_KINDS = { exclude: "Leave out matching events", disable: "Switch off for this client", severity: "Set the severity" } as const;
export type TuningKind = keyof typeof TUNING_KINDS;
export const TUNING_FIELDS = { host: "Host", user: "Account", process: "Process", ip: "IP address", text: "Anywhere in the event" } as const;
export type TuningField = keyof typeof TUNING_FIELDS;
export const TUNING_OPS = { equals: "is", contains: "contains", startswith: "starts with", endswith: "ends with", regex: "matches regex" } as const;
export type TuningOp = keyof typeof TUNING_OPS;

export interface Tuning {
  id: string;
  target: string;
  kind: TuningKind;
  field?: TuningField | null;
  op?: TuningOp | null;
  value?: string | null;
  severity?: CaseSeverity | null;
  expiresAt?: Date | null;
}

// The name a detection is tuned by: the detector, or "sigma:<id>".
export const targetOf = (d: Pick<ScoredDetection, "detector" | "ruleId">) => (d.detector === "sigma" ? `sigma:${d.ruleId}` : d.detector);

const RISK: Record<CaseSeverity, number> = { CRITICAL: 900, HIGH: 600, MEDIUM: 300, LOW: 50, INFO: 10 };

function fieldValues(e: UnifiedEvent, field: TuningField): string[] {
  switch (field) {
    case "host":
      return [e.actor.host ?? ""];
    case "user":
      return [e.actor.user ?? ""];
    case "process":
      return [e.actor.process ?? "", String(e.metadata.commandLine ?? "")];
    case "ip":
      return [e.network.sourceIp ?? "", e.network.destIp ?? ""];
    case "text":
      return [e.actor.host, e.actor.user, e.actor.process, e.actor.service, e.network.sourceIp, e.network.destIp, e.eventType, JSON.stringify(e.metadata)].filter((x): x is string => !!x);
  }
}

export function validRegex(value: string) {
  try {
    new RegExp(value, "i");
    return value.length <= 300;
  } catch {
    return false;
  }
}

export function eventMatches(t: Pick<Tuning, "field" | "op" | "value">, e: UnifiedEvent): boolean {
  if (!t.field || !t.op || !t.value) return false;
  const want = t.value.toLowerCase();
  const re = t.op === "regex" && validRegex(t.value) ? new RegExp(t.value, "i") : null;
  return fieldValues(e, t.field).some((raw) => {
    const v = raw.toLowerCase();
    if (!v) return false;
    switch (t.op) {
      case "equals":
        return v === want;
      case "contains":
        return v.includes(want);
      case "startswith":
        return v.startsWith(want);
      case "endswith":
        return v.endsWith(want);
      case "regex":
        return !!re && re.test(raw);
      default:
        return false;
    }
  });
}

export interface TuningOutcome {
  detections: ScoredDetection[];
  // Tuning id → detections it held back or changed.
  hits: Map<string, number>;
  suppressed: number;
}

export function applyTuning(detections: ScoredDetection[], tunings: Tuning[], now = new Date()): TuningOutcome {
  const live = tunings.filter((t) => !t.expiresAt || t.expiresAt > now);
  const hits = new Map<string, number>();
  const hit = (t: Tuning) => hits.set(t.id, (hits.get(t.id) ?? 0) + 1);
  const out: ScoredDetection[] = [];
  let suppressed = 0;
  for (const d of detections) {
    const target = targetOf(d);
    const mine = live.filter((t) => t.target === "*" || t.target === target);
    const off = mine.find((t) => t.kind === "disable");
    if (off) {
      hit(off);
      suppressed++;
      continue;
    }
    let events = d.matchedEvents;
    for (const t of mine.filter((x) => x.kind === "exclude")) {
      const kept = events.filter((e) => !eventMatches(t, e));
      if (kept.length < events.length) hit(t);
      events = kept;
    }
    if (!events.length) {
      suppressed++;
      continue;
    }
    let next: ScoredDetection = events === d.matchedEvents ? d : { ...d, matchedEvents: events };
    const sev = mine.find((t) => t.kind === "severity" && t.severity);
    if (sev?.severity) {
      hit(sev);
      next = { ...next, riskScore: RISK[sev.severity], reasoning: [...next.reasoning, `Severity set to ${sev.severity.toLowerCase()} for this client by tuning`] };
    }
    out.push(next);
  }
  return { detections: out, hits, suppressed };
}
