import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const geoVelocityDetector: Detector = {
  name: "GeoVelocityDetector",
  description: "Detects impossible travel between login events from different locations.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    const loginsByUser = new Map<string, NormalizedEvent[]>();

    events
      .filter((e) => e.eventType === "LOGIN_SUCCESS" && e.actor.user)
      .forEach((e) => {
        const list = loginsByUser.get(e.actor.user!) ?? [];
        list.push(e);
        loginsByUser.set(e.actor.user!, list);
      });

    for (const [user, userEvents] of loginsByUser) {
      const sorted = [...userEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

      for (let i = 0; i < sorted.length - 1; i++) {
        const current = sorted[i];
        const next = sorted[i + 1];

        if (current.network.geo && next.network.geo && current.network.geo !== next.network.geo) {
          const timeDiffHours = (next.timestamp.getTime() - current.timestamp.getTime()) / (1000 * 60 * 60);
          const distanceKm = 1000; // different-geo login pair assumed >= 1000km apart
          const velocity = distanceKm / timeDiffHours;

          if (timeDiffHours > 0 && velocity > 900) {
            detections.push({
              detector: geoVelocityDetector.name,
              matchedEvents: [current, next],
              signals: ["impossible_travel", "geo_anomaly"],
              confidence: 0.9,
              mitreTactics: ["Initial Access", "Credential Access"],
              mitreTechniques: ["T1078 - Valid Accounts"],
              reasoning: [
                `User ${user} logged in from ${current.network.geo} then ${next.network.geo} within ${timeDiffHours.toFixed(2)}h.`,
                `Calculated velocity ${velocity.toFixed(0)} km/h exceeds physical limits.`,
              ],
            });
          }
        }
      }
    }

    return detections;
  },
};
