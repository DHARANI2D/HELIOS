import type { Detector, DetectionResult, NormalizedEvent } from "../types";
import { SecurityPolicy } from "../policy";

const maliciousIps = new Set(SecurityPolicy.threatIntel.maliciousIps);
const suspiciousProcesses = SecurityPolicy.threatIntel.suspiciousProcesses;

export const threatIntelDetector: Detector = {
  name: "ThreatIntelDetector",
  description: "Matches events against known malicious indicators (IPs, processes).",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    for (const event of events) {
      const signals: string[] = [];
      const reasoning: string[] = [];

      if (event.network.sourceIp && maliciousIps.has(event.network.sourceIp)) {
        signals.push("intel_malicious_ip");
        reasoning.push(`Matched known malicious IP: ${event.network.sourceIp}`);
      }

      if (event.actor.process) {
        const procLower = event.actor.process.toLowerCase();
        const bad = suspiciousProcesses.find((p) => procLower.includes(p));
        if (bad) {
          signals.push("intel_suspicious_process");
          reasoning.push(`Detected suspicious process execution: ${event.actor.process}`);
        }
      }

      if (signals.length > 0) {
        detections.push({
          detector: threatIntelDetector.name,
          matchedEvents: [event],
          signals,
          confidence: 0.9,
          mitreTactics: ["Command and Control", "Initial Access"],
          mitreTechniques: [
            "T1071 - Application Layer Protocol",
            "T1190 - Exploit Public-Facing Application",
          ],
          reasoning,
        });
      }
    }

    return detections;
  },
};
