import type { Detection, Detector, UnifiedEvent } from "@/lib/siem/types";
import { GEO_CENTROIDS, SecurityPolicy } from "@/lib/siem/policy";
import { localVerdict } from "@/lib/threat-intel/local-intel";

// Ported from signal-fusion's detection/detectors/{geoVelocity,fsmChain,
// anomalousAction,threatIntel}.ts — the four original correlation detectors.

function byUser(events: UnifiedEvent[]) {
  const groups = new Map<string, UnifiedEvent[]>();
  for (const e of events) {
    if (!e.actor.user) continue;
    const list = groups.get(e.actor.user) ?? [];
    list.push(e);
    groups.set(e.actor.user, list);
  }
  for (const list of groups.values()) list.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  return groups;
}

function haversineKm([lat1, lon1]: [number, number], [lat2, lon2]: [number, number]) {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * 6371 * Math.asin(Math.sqrt(a));
}

export function geoDistanceKm(a: string, b: string): number {
  const ca = GEO_CENTROIDS[a.toLowerCase()];
  const cb = GEO_CENTROIDS[b.toLowerCase()];
  return ca && cb ? haversineKm(ca, cb) : SecurityPolicy.geoVelocity.unknownDistanceKm;
}

export const geoVelocityDetector: Detector = {
  name: "Geo-Velocity Detector",
  detectionSource: "GEO_VELOCITY",
  description: "Impossible travel between successful logins from different locations.",
  techniques: ["T1078"],
  run(events) {
    const detections: Detection[] = [];
    const logins = events.filter((e) => e.eventType === "LOGIN_SUCCESS" && e.network.geo);
    for (const [user, list] of byUser(logins)) {
      for (let i = 0; i < list.length - 1; i++) {
        const current = list[i];
        const next = list[i + 1];
        const from = current.network.geo!;
        const to = next.network.geo!;
        if (from.toLowerCase() === to.toLowerCase()) continue;

        const hours = (next.timestamp.getTime() - current.timestamp.getTime()) / 3_600_000;
        if (hours <= 0) continue;
        const km = geoDistanceKm(from, to);
        const velocity = km / hours;
        if (velocity <= SecurityPolicy.geoVelocity.maxKmPerHour) continue;

        detections.push({
          detector: this.name,
          detectionSource: this.detectionSource,
          ruleId: "impossible_travel",
          matchedEvents: [current, next],
          signals: ["impossible_travel", "geo_anomaly"],
          confidence: 0.9,
          mitreTactics: ["Initial Access", "Credential Access"],
          mitreTechniques: ["T1078 - Valid Accounts"],
          reasoning: [
            `User ${user} logged in from ${from} and then ${to} within ${hours.toFixed(2)} hours.`,
            `~${Math.round(km)} km at ${Math.round(velocity)} km/h exceeds the ${SecurityPolicy.geoVelocity.maxKmPerHour} km/h travel limit.`,
          ],
        });
      }
    }
    return detections;
  },
};

export const fsmChainDetector: Detector = {
  name: "FSM-Chain Detector",
  detectionSource: "FSM_CHAIN",
  description: "Failed login → successful login → sensitive action, tracked as a finite state machine.",
  techniques: ["T1078", "T1110", "T1548"],
  run(events) {
    const detections: Detection[] = [];
    const { sensitiveSources, maxChainTimeGapMs } = SecurityPolicy.fsmChain;

    for (const [user, list] of byUser(events)) {
      let state: "START" | "FAILED_LOGIN" | "SUCCESS_LOGIN" = "START";
      let chain: UnifiedEvent[] = [];

      for (const event of list) {
        // signal-fusion declared maxChainTimeGapMs but never enforced it, so
        // a failed login on Monday could chain with a sensitive action on Friday.
        const last = chain[chain.length - 1];
        if (last && event.timestamp.getTime() - last.timestamp.getTime() > maxChainTimeGapMs) {
          state = "START";
          chain = [];
        }

        if (event.eventType === "LOGIN_FAIL" && (state === "START" || state === "FAILED_LOGIN")) {
          state = "FAILED_LOGIN";
          chain.push(event);
        } else if (state === "FAILED_LOGIN" && event.eventType === "LOGIN_SUCCESS") {
          state = "SUCCESS_LOGIN";
          chain.push(event);
        } else if (state === "SUCCESS_LOGIN" && sensitiveSources.includes(event.source)) {
          detections.push({
            detector: this.name,
            detectionSource: this.detectionSource,
            ruleId: "login_chain_sensitive_action",
            matchedEvents: [...chain, event],
            signals: ["suspicious_login_chain", "potential_account_takeover"],
            confidence: 0.85,
            mitreTactics: ["Persistence", "Privilege Escalation"],
            mitreTechniques: ["T1078 - Valid Accounts", "T1548 - Abuse Elevation Control Mechanism"],
            reasoning: [
              `User ${user} had ${chain.length - 1} failed login(s) followed by a success, then a sensitive ${event.source} action.`,
              `Action: ${event.eventType} on ${event.actor.service ?? event.actor.process ?? "unknown"}.`,
            ],
          });
          state = "START";
          chain = [];
        }
      }
    }
    return detections;
  },
};

const DISCOVERY_PROCESSES = ["whoami", "net user", "ipconfig", "systeminfo", "tasklist", "quser"];
const SUSPICIOUS_NEXT_STEP = ["powershell", "cmd.exe", "schtasks", "reg.exe", "bitsadmin", "certutil"];

export const anomalousActionDetector: Detector = {
  name: "Anomalous Action Detector",
  detectionSource: "ANOMALOUS_ACTION",
  description: "Discovery command immediately followed by a living-off-the-land execution step.",
  techniques: ["T1087", "T1059"],
  run(events) {
    const detections: Detection[] = [];
    for (const [user, list] of byUser(events)) {
      for (let i = 0; i < list.length - 1; i++) {
        const e1 = list[i];
        const e2 = list[i + 1];
        const p1 = (e1.actor.process ?? "").toLowerCase();
        const p2 = (e2.actor.process ?? "").toLowerCase();
        if (e1.eventType !== "PROCESS_START" || e2.eventType !== "PROCESS_START") continue;
        if (!DISCOVERY_PROCESSES.some((d) => p1.includes(d))) continue;
        if (!SUSPICIOUS_NEXT_STEP.some((s) => p2.includes(s))) continue;

        detections.push({
          detector: this.name,
          detectionSource: this.detectionSource,
          ruleId: "discovery_then_execution",
          matchedEvents: [e1, e2],
          signals: ["discovery_followed_by_suspicious_action", "lateral_movement_prep"],
          confidence: 0.7,
          mitreTactics: ["Discovery", "Execution"],
          mitreTechniques: ["T1087 - Account Discovery", "T1059 - Command and Scripting Interpreter"],
          reasoning: [
            `User ${user} ran discovery command '${e1.actor.process}' followed by '${e2.actor.process}'.`,
            `Time gap: ${Math.round((e2.timestamp.getTime() - e1.timestamp.getTime()) / 1000)}s`,
          ],
        });
      }
    }
    return detections;
  },
};

export const threatIntelDetector: Detector = {
  name: "ThreatIntelDetector",
  detectionSource: "THREAT_INTEL_MATCH",
  description: "Events touching known-malicious IPs or known attacker tooling.",
  techniques: ["T1071", "T1190"],
  run(events, ctx) {
    const detections: Detection[] = [];
    const suspiciousProcesses = SecurityPolicy.threatIntel.suspiciousProcesses;

    for (const event of events) {
      const signals: string[] = [];
      const reasoning: string[] = [];

      // signal-fusion only checked the source IP; outbound beacons to a known
      // C2 show up as the destination instead.
      for (const [role, ip] of [["source", event.network.sourceIp], ["destination", event.network.destIp]] as const) {
        if (!ip) continue;
        const verdict = localVerdict("IP", ip, ctx.intel);
        if (verdict.score >= 0.7) {
          signals.push("intel_malicious_ip");
          reasoning.push(`Matched threat intel for ${role} IP ${ip} (${verdict.reasons.join("; ")})`);
        }
      }

      const proc = event.actor.process?.toLowerCase();
      const bad = proc && suspiciousProcesses.find((p) => proc.includes(p));
      if (bad) {
        signals.push("intel_suspicious_process");
        reasoning.push(`Known attacker tooling executed: ${event.actor.process}`);
      }

      if (signals.length) {
        detections.push({
          detector: this.name,
          detectionSource: this.detectionSource,
          ruleId: signals.includes("intel_malicious_ip") ? "known_bad_ip" : "known_bad_tool",
          matchedEvents: [event],
          signals: [...new Set(signals)],
          confidence: 0.9,
          mitreTactics: ["Command and Control", "Initial Access"],
          mitreTechniques: ["T1071 - Application Layer Protocol", "T1190 - Exploit Public-Facing Application"],
          reasoning,
        });
      }
    }
    return detections;
  },
};
