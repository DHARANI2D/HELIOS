import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const persistenceDetector: Detector = {
  name: "PersistenceDetector",
  description: "Detects persistence mechanisms: registry run keys, scheduled tasks, services.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source !== "ENDPOINT" || !event.actor.process) return;
      const process = event.actor.process.toLowerCase();

      if (process.includes("reg add") && process.includes("\\currentversion\\run")) {
        detections.push({
          detector: persistenceDetector.name,
          matchedEvents: [event],
          signals: ["registry_persistence", "autostart_execution"],
          confidence: 0.9,
          mitreTactics: ["Persistence"],
          mitreTechniques: ["T1547 - Boot or Logon Autostart Execution"],
          reasoning: [`Registry run key modification: ${event.actor.process}`],
        });
      }

      if (process.includes("schtasks /create") || process.includes("at ") || process.includes("crontab")) {
        detections.push({
          detector: persistenceDetector.name,
          matchedEvents: [event],
          signals: ["scheduled_task_persistence"],
          confidence: 0.85,
          mitreTactics: ["Persistence", "Execution"],
          mitreTechniques: ["T1053 - Scheduled Task/Job"],
          reasoning: [`Scheduled task creation: ${event.actor.process}`],
        });
      }

      if (process.includes("sc create") || process.includes("new-service")) {
        detections.push({
          detector: persistenceDetector.name,
          matchedEvents: [event],
          signals: ["service_persistence"],
          confidence: 0.9,
          mitreTactics: ["Persistence"],
          mitreTechniques: ["T1543 - Create or Modify System Process"],
          reasoning: [`Service creation detected: ${event.actor.process}`],
        });
      }
    });

    return detections;
  },
};
