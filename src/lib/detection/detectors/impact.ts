import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const impactDetector: Detector = {
  name: "ImpactDetector",
  description: "Detects ransomware, data destruction, and service disruption.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source !== "ENDPOINT") return;
      const process = event.actor.process?.toLowerCase() ?? "";
      const filesModified = Number(event.metadata?.files_modified ?? 0);

      if (process.includes("ransomware") || process.includes("encrypt") || filesModified > 1000) {
        detections.push({
          detector: impactDetector.name,
          matchedEvents: [event],
          signals: ["ransomware", "mass_encryption"],
          confidence: 0.95,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1486 - Data Encrypted for Impact"],
          reasoning: [
            "Potential ransomware activity",
            filesModified ? `${filesModified} files modified` : `Process: ${event.actor.process}`,
          ],
        });
      }

      if (process.includes("del /f /s /q") || process.includes("rm -rf")) {
        detections.push({
          detector: impactDetector.name,
          matchedEvents: [event],
          signals: ["data_destruction", "mass_deletion"],
          confidence: 0.85,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1485 - Data Destruction"],
          reasoning: [`Mass file deletion: ${event.actor.process}`],
        });
      }

      if (process.includes("net stop") || process.includes("sc stop")) {
        detections.push({
          detector: impactDetector.name,
          matchedEvents: [event],
          signals: ["service_disruption"],
          confidence: 0.75,
          mitreTactics: ["Impact"],
          mitreTechniques: ["T1489 - Service Stop"],
          reasoning: [`Service stopped: ${event.actor.process}`],
        });
      }
    });

    return detections;
  },
};
