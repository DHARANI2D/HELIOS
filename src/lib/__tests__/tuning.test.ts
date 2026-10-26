import { describe, expect, it } from "vitest";

import { applyTuning, type Tuning } from "@/lib/detections/tuning";
import type { ScoredDetection, UnifiedEvent } from "@/lib/siem/types";

const event = (host: string, user = "svc_backup", process = "powershell.exe -enc AAAA"): UnifiedEvent => ({ id: `${host}-${user}`, timestamp: new Date(), source: "endpoint", eventType: "PROCESS_START", actor: { host, user, process }, network: {}, severityHint: "high", metadata: {} });
const detection = (detector: string, events: UnifiedEvent[], ruleId = "r1"): ScoredDetection => ({ detector, detectionSource: "DEFENSE_EVASION", ruleId, matchedEvents: events, signals: [], confidence: 0.8, reasoning: [], mitreTactics: [], mitreTechniques: [], riskScore: 500, riskObject: "x", riskObjectType: "host" });

describe("per-client tuning", () => {
  it("leaves out known-good events, switches detectors off, sets severity and counts what it did", () => {
    const tunings: Tuning[] = [
      { id: "ex", target: "Defense Evasion", kind: "exclude", field: "host", op: "equals", value: "build-01" },
      { id: "off", target: "Reconnaissance", kind: "disable" },
      { id: "sev", target: "sigma:abc", kind: "severity", severity: "HIGH" },
      { id: "old", target: "*", kind: "disable", expiresAt: new Date(Date.now() - 1000) },
    ];
    const r = applyTuning(
      [
        detection("Defense Evasion", [event("BUILD-01"), event("WS-02")]),
        detection("Defense Evasion", [event("BUILD-01")]),
        detection("Reconnaissance", [event("WS-03")]),
        detection("sigma", [event("WS-04")], "abc"),
      ],
      tunings,
    );
    expect(r.detections.map((d) => [d.detector, d.matchedEvents.map((e) => e.actor.host), d.riskScore])).toEqual([
      ["Defense Evasion", ["WS-02"], 500],
      ["sigma", ["WS-04"], 600],
    ]);
    expect(r.suppressed).toBe(2);
    expect(Object.fromEntries(r.hits)).toEqual({ ex: 2, off: 1, sev: 1 });
  });

  it("matches the other fields and tests", () => {
    const d = [detection("X", [event("WS-1", "jdoe", "C:\\Tools\\backup.exe --nightly")])];
    const kept = (t: Partial<Tuning>) => applyTuning(d, [{ id: "t", target: "*", kind: "exclude", ...t } as Tuning]).detections.length;
    expect(kept({ field: "process", op: "contains", value: "BACKUP.EXE" })).toBe(0);
    expect(kept({ field: "user", op: "startswith", value: "jd" })).toBe(0);
    expect(kept({ field: "process", op: "regex", value: "--night(ly)?$" })).toBe(0);
    expect(kept({ field: "text", op: "contains", value: "ws-1" })).toBe(0);
    expect(kept({ field: "host", op: "endswith", value: "-2" })).toBe(1);
    expect(kept({ field: "process", op: "regex", value: "([" })).toBe(1);
  });
});
