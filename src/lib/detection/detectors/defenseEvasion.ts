import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const defenseEvasionDetector: Detector = {
  name: "DefenseEvasionDetector",
  description: "Detects log clearing, security-tool disabling, obfuscated commands.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source !== "ENDPOINT" || !event.actor.process) return;
      const process = event.actor.process.toLowerCase();

      if (process.includes("wevtutil") && process.includes("cl")) {
        detections.push({
          detector: defenseEvasionDetector.name,
          matchedEvents: [event],
          signals: ["log_clearing", "anti_forensics"],
          confidence: 0.95,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1070.001 - Clear Windows Event Logs"],
          reasoning: [`Event log clearing detected: ${event.actor.process}`],
        });
      }

      if (process.includes("set-mppreference") && process.includes("disablerealtimemonitoring")) {
        detections.push({
          detector: defenseEvasionDetector.name,
          matchedEvents: [event],
          signals: ["disable_av", "impair_defenses"],
          confidence: 0.95,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1562 - Impair Defenses"],
          reasoning: [`Antivirus disabled: ${event.actor.process}`],
        });
      }

      if (process.includes("-enc ") || process.includes("base64")) {
        detections.push({
          detector: defenseEvasionDetector.name,
          matchedEvents: [event],
          signals: ["obfuscation", "encoded_command"],
          confidence: 0.7,
          mitreTactics: ["Defense Evasion"],
          mitreTechniques: ["T1027 - Obfuscated Files or Information"],
          reasoning: [`Obfuscated command: ${event.actor.process}`],
        });
      }
    });

    return detections;
  },
};
