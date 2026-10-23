import { describe, expect, it } from "vitest";

import { normalize } from "@/lib/siem/adapters";
import { DETECTORS, fingerprintFor, riskScoreFor, runDetections, severityForRisk } from "@/lib/siem/engine";
import { allScenarios, selectScenarios } from "@/lib/siem/simulation";
import { geoDistanceKm } from "@/lib/siem/detectors/behavioral";
import type { TelemetrySource, UnifiedEvent } from "@/lib/siem/types";

let seq = 0;
function ev(source: TelemetrySource, data: Record<string, unknown>): UnifiedEvent {
  return { id: `e${++seq}`, ...normalize(source, data) };
}
const at = (minutes: number) => new Date(Date.UTC(2026, 9, 20, 8, minutes)).toISOString();

describe("adapters", () => {
  it("normalizes auth results into login event types", () => {
    expect(ev("auth", { user: "a", result: "FAILED" }).eventType).toBe("LOGIN_FAIL");
    expect(ev("auth", { user: "a", result: "SUCCESS", geo_location: "Russia" }).network.geo).toBe("Russia");
  });

  it("accepts both src_ip/dst_ip and source_ip/dest_ip on network logs", () => {
    expect(ev("network", { src_ip: "1.1.1.1", dst_ip: "2.2.2.2", port: 443 }).network).toMatchObject({ sourceIp: "1.1.1.1", destIp: "2.2.2.2", destPort: 443 });
    expect(ev("network", { source_ip: "3.3.3.3", dest_ip: "4.4.4.4" }).network).toMatchObject({ sourceIp: "3.3.3.3", destIp: "4.4.4.4" });
  });

  it("carries endpoint host and parent process", () => {
    const e = ev("endpoint", { user: "u", process: "cmd.exe", parent_process: "winword.exe", hostname: "ws-1" });
    expect(e.actor).toMatchObject({ user: "u", process: "cmd.exe", host: "ws-1" });
    expect(e.metadata.parentProcess).toBe("winword.exe");
  });
});

describe("detectors", () => {
  it("flags credential dumping as a critical-risk detection", () => {
    const [d] = runDetections([ev("endpoint", { user: "u", process: "mimikatz.exe sekurlsa::logonpasswords", hostname: "ws-1" })]).filter(
      (x) => x.detectionSource === "CREDENTIAL_HARVESTING",
    );
    expect(d).toBeDefined();
    expect(severityForRisk(d.riskScore)).toBe("CRITICAL");
    expect(d.riskObject).toBe("u");
  });

  it("does not treat 'cat ' as the at.exe scheduler (signal-fusion false positive)", () => {
    const detections = runDetections([ev("endpoint", { user: "u", process: "cat /etc/os-release" })]);
    expect(detections.some((d) => d.ruleId === "scheduled_task")).toBe(false);
    expect(runDetections([ev("endpoint", { user: "u", process: "at 13:00 /every:M evil.exe" })]).some((d) => d.ruleId === "scheduled_task")).toBe(true);
  });

  it("detects impossible travel using real distances", () => {
    expect(geoDistanceKm("Russia", "USA")).toBeGreaterThan(5000);
    const d = runDetections([
      ev("auth", { user: "j", result: "SUCCESS", geo_location: "USA", timestamp: at(0) }),
      ev("auth", { user: "j", result: "SUCCESS", geo_location: "Russia", timestamp: at(60) }),
    ]).filter((x) => x.detectionSource === "GEO_VELOCITY");
    expect(d).toHaveLength(1);
  });

  it("does not flag plausible travel between neighbouring countries", () => {
    const d = runDetections([
      ev("auth", { user: "k", result: "SUCCESS", geo_location: "France", timestamp: at(0) }),
      ev("auth", { user: "k", result: "SUCCESS", geo_location: "Germany", timestamp: new Date(Date.UTC(2026, 9, 20, 12, 0)).toISOString() }),
    ]).filter((x) => x.detectionSource === "GEO_VELOCITY");
    expect(d).toHaveLength(0);
  });

  it("enforces the FSM chain's 30-minute gap", () => {
    const chain = (gapMinutes: number) =>
      runDetections([
        ev("auth", { user: "f", result: "FAILED", timestamp: at(0) }),
        ev("auth", { user: "f", result: "SUCCESS", timestamp: at(1) }),
        ev("cloud", { user: "f", action: "DELETE_BUCKET", resource: "prod", timestamp: at(1 + gapMinutes) }),
      ]).filter((x) => x.detectionSource === "FSM_CHAIN");
    expect(chain(5)).toHaveLength(1);
    expect(chain(45)).toHaveLength(0);
  });

  it("detects password spraying from one source IP", () => {
    const events = ["a", "b", "c", "d", "e"].map((u) => ev("auth", { user: u, source_ip: "203.0.113.9", result: "FAILED" }));
    expect(runDetections(events).some((d) => d.ruleId === "password_spraying")).toBe(true);
  });

  it("matches threat intel on destination as well as source IPs", () => {
    const d = runDetections([ev("network", { source_ip: "10.0.0.2", dest_ip: "99.88.77.66", port: 443 })]);
    expect(d.some((x) => x.detectionSource === "THREAT_INTEL_MATCH")).toBe(true);
  });
});

describe("risk scoring and fingerprints", () => {
  it("multiplies confidence by signal family", () => {
    expect(riskScoreFor({ confidence: 0.95, signals: ["ransomware"] })).toBe(950);
    expect(riskScoreFor({ confidence: 0.8, signals: ["lateral_movement"] })).toBe(560);
    expect(riskScoreFor({ confidence: 0.5, signals: ["anomalous_x"] })).toBe(200);
    expect(riskScoreFor({ confidence: 0.5, signals: ["other"] })).toBe(100);
    expect(severityForRisk(700)).toBe("CRITICAL");
    expect(severityForRisk(99)).toBe("LOW");
  });

  it("fingerprints are independent of matched-event order", () => {
    const [a, b] = [ev("endpoint", { process: "x" }), ev("endpoint", { process: "y" })];
    const base = { detector: "D", detectionSource: "IMPACT" as const, ruleId: "r", signals: [], confidence: 1, reasoning: [], mitreTactics: [], mitreTechniques: [] };
    expect(fingerprintFor({ ...base, matchedEvents: [a, b] })).toBe(fingerprintFor({ ...base, matchedEvents: [b, a] }));
    expect(fingerprintFor({ ...base, matchedEvents: [a] })).not.toBe(fingerprintFor({ ...base, matchedEvents: [b] }));
  });
});

describe("attack simulation", () => {
  it("ports all 48 signal-fusion scenarios", () => {
    expect(allScenarios()).toHaveLength(48);
    expect(new Set(allScenarios().map((s) => s.id)).size).toBe(48);
  });

  it("replaying every scenario exercises most detectors", () => {
    const events = allScenarios().flatMap((s) => s.logs.map((l) => ev(l.source, l.data)));
    const fired = new Set(runDetections(events).map((d) => d.detector));
    expect(fired.size).toBeGreaterThanOrEqual(8);
    expect(DETECTORS.length).toBe(11);
  });

  it("selects scenarios by tactic, id, and seeded random sample", () => {
    expect(selectScenarios({ scenarioIds: ["ia-001"] }).map((s) => s.id)).toEqual(["ia-001"]);
    expect(selectScenarios({ tactics: ["Impact"] }).every((s) => s.mitreTactics.includes("Impact"))).toBe(true);
    const high = selectScenarios({ count: 5, intensity: "high" }, () => 0.42);
    expect(high).toHaveLength(5);
    expect(high.every((s) => s.severity === "High")).toBe(true);
  });
});
