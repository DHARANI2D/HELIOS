import type { Detector, DetectionResult, NormalizedEvent } from "../types";
import { SecurityPolicy } from "../policy";

export const fsmChainDetector: Detector = {
  name: "FSMChainDetector",
  description:
    "Tracks attack chains via a state machine (e.g. BRUTE_FORCE -> SUCCESS -> SENSITIVE_ACTION).",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    const eventsByUser = new Map<string, NormalizedEvent[]>();
    const sensitiveSources: readonly string[] = SecurityPolicy.fsmChain.sensitiveSources;

    events
      .filter((e) => e.actor.user)
      .forEach((e) => {
        const list = eventsByUser.get(e.actor.user!) ?? [];
        list.push(e);
        eventsByUser.set(e.actor.user!, list);
      });

    for (const [user, userEvents] of eventsByUser) {
      const sorted = [...userEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

      let state: "START" | "FAILED_LOGIN" | "SUCCESS_LOGIN" = "START";
      let chain: NormalizedEvent[] = [];

      for (const event of sorted) {
        if (state === "START" && event.eventType === "LOGIN_FAIL") {
          state = "FAILED_LOGIN";
          chain = [event];
        } else if (state === "FAILED_LOGIN" && event.eventType === "LOGIN_SUCCESS") {
          state = "SUCCESS_LOGIN";
          chain.push(event);
        } else if (state === "SUCCESS_LOGIN" && sensitiveSources.includes(event.source)) {
          detections.push({
            detector: fsmChainDetector.name,
            matchedEvents: [...chain, event],
            signals: ["suspicious_login_chain", "potential_account_takeover"],
            confidence: 0.85,
            mitreTactics: ["Persistence", "Privilege Escalation"],
            mitreTechniques: [
              "T1078 - Valid Accounts",
              "T1548 - Abuse Elevation Control Mechanism",
            ],
            reasoning: [
              `User ${user} had a FAILED_LOGIN then SUCCESS_LOGIN, then a sensitive action in ${event.source}.`,
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
