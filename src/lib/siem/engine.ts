import { createHash } from "node:crypto";
import type { CaseSeverity } from "@prisma/client";

import type { Detection, DetectionContext, Detector, ScoredDetection, UnifiedEvent } from "@/lib/siem/types";
import { EMPTY_INTEL } from "@/lib/threat-intel/local-intel";
import {
  anomalousActionDetector,
  fsmChainDetector,
  geoVelocityDetector,
  threatIntelDetector,
} from "@/lib/siem/detectors/behavioral";
import {
  credentialHarvestingDetector,
  dataExfiltrationDetector,
  defenseEvasionDetector,
  impactDetector,
  lateralMovementDetector,
  persistenceDetector,
  reconnaissanceDetector,
} from "@/lib/siem/detectors/techniques";

// Ported from signal-fusion's detection/engine.ts. The pure half — run every
// detector, score the results — lives here so it can be unit-tested; turning
// detections into correlated Cases is lib/siem/service.ts.

export const DETECTORS: Detector[] = [
  geoVelocityDetector,
  fsmChainDetector,
  anomalousActionDetector,
  threatIntelDetector,
  reconnaissanceDetector,
  credentialHarvestingDetector,
  lateralMovementDetector,
  dataExfiltrationDetector,
  persistenceDetector,
  defenseEvasionDetector,
  impactDetector,
];

const CRITICAL_SIGNALS = ["ransomware", "credential_dumping", "mimikatz", "data_destruction"];
const HIGH_SIGNALS = ["lateral_movement", "exfiltration", "persistence", "privilege_escalation", "malware", "kerberos", "pass_the_hash", "intel_malicious_ip"];
const MEDIUM_SIGNALS = ["reconnaissance", "discovery", "suspicious", "anomalous", "obfuscation", "scanning"];

// signal-fusion's enterprise risk model: confidence (0-100) × a multiplier
// chosen by the most severe signal family, capped at 1000.
export function riskScoreFor(detection: Pick<Detection, "confidence" | "signals">): number {
  const signals = detection.signals.map((s) => s.toLowerCase());
  const has = (list: string[]) => signals.some((s) => list.some((k) => s.includes(k)));
  const multiplier = has(CRITICAL_SIGNALS) ? 10 : has(HIGH_SIGNALS) ? 7 : has(MEDIUM_SIGNALS) ? 4 : 2;
  return Math.min(Math.round(detection.confidence * 100 * multiplier), 1000);
}

export function severityForRisk(riskScore: number): CaseSeverity {
  if (riskScore >= 700) return "CRITICAL";
  if (riskScore >= 400) return "HIGH";
  if (riskScore >= 100) return "MEDIUM";
  return "LOW";
}

// Who the detection is "about" — the correlation key for grouping detections
// into one case. Users beat hosts beat IPs, matching how analysts pivot.
export function riskObjectFor(detection: Detection): Pick<ScoredDetection, "riskObject" | "riskObjectType"> {
  const first = detection.matchedEvents.find((e) => e.actor.user && e.actor.user !== "unknown") ?? detection.matchedEvents[0];
  if (first?.actor.user && first.actor.user !== "unknown") return { riskObject: first.actor.user, riskObjectType: "user" };
  const host = detection.matchedEvents.find((e) => e.actor.host)?.actor.host;
  if (host) return { riskObject: host, riskObjectType: "host" };
  const ip = detection.matchedEvents.find((e) => e.network.sourceIp)?.network.sourceIp;
  if (ip) return { riskObject: ip, riskObjectType: "ip" };
  return { riskObject: "unknown", riskObjectType: "unknown" };
}

// Same detector + rule over the same events = same finding, however many
// times detection re-runs over an overlapping window.
export function fingerprintFor(detection: Detection): string {
  const ids = detection.matchedEvents.map((e) => e.id).sort().join(",");
  return createHash("sha256").update(`${detection.detector}|${detection.ruleId}|${ids}`).digest("hex");
}

export function runDetections(events: UnifiedEvent[], ctx: DetectionContext = { intel: EMPTY_INTEL }): ScoredDetection[] {
  const out: ScoredDetection[] = [];
  for (const detector of DETECTORS) {
    if (ctx.disabled?.includes(detector.name)) continue;
    for (const detection of detector.run(events, ctx)) {
      out.push({ ...detection, riskScore: riskScoreFor(detection), ...riskObjectFor(detection) });
    }
  }
  return out;
}
