import type { Detector, DetectionResult, NormalizedEvent } from "../types";

const DISCOVERY_PROCESSES = ["whoami", "net user", "ipconfig", "systeminfo", "tasklist", "quser"];
const SUSPICIOUS_NEXT_STEPS = ["powershell", "cmd.exe", "schtasks", "reg.exe", "bitsadmin", "certutil"];

export const anomalousActionDetector: Detector = {
  name: "AnomalousActionDetector",
  description:
    "Detects suspicious event sequences within a short timeframe (e.g. discovery command followed by execution).",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    const eventsByUser = new Map<string, NormalizedEvent[]>();

    events
      .filter((e) => e.actor.user)
      .forEach((e) => {
        const list = eventsByUser.get(e.actor.user!) ?? [];
        list.push(e);
        eventsByUser.set(e.actor.user!, list);
      });

    for (const [user, userEvents] of eventsByUser) {
      const sorted = [...userEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

      for (let i = 0; i < sorted.length - 1; i++) {
        const e1 = sorted[i];
        const e2 = sorted[i + 1];

        if (
          e1.eventType === "PROCESS_START" &&
          DISCOVERY_PROCESSES.some((d) => (e1.actor.process ?? "").toLowerCase().includes(d)) &&
          e2.eventType === "PROCESS_START" &&
          SUSPICIOUS_NEXT_STEPS.some((s) => (e2.actor.process ?? "").toLowerCase().includes(s))
        ) {
          detections.push({
            detector: anomalousActionDetector.name,
            matchedEvents: [e1, e2],
            signals: ["discovery_followed_by_suspicious_action", "lateral_movement_prep"],
            confidence: 0.7,
            mitreTactics: ["Discovery", "Execution"],
            mitreTechniques: [
              "T1087 - Account Discovery",
              "T1059 - Command and Scripting Interpreter",
            ],
            reasoning: [
              `User ${user} ran discovery process '${e1.actor.process}' then suspicious process '${e2.actor.process}'.`,
              `Time gap: ${Math.round((e2.timestamp.getTime() - e1.timestamp.getTime()) / 1000)}s`,
            ],
          });
        }
      }
    }

    return detections;
  },
};
