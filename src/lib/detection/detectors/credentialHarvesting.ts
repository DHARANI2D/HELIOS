import type { Detector, DetectionResult, NormalizedEvent } from "../types";

const DUMPING_TOOLS = ["mimikatz", "procdump", "pwdump", "gsecdump", "wce.exe", "lsass"];
const KEYLOGGERS = ["keylogger", "keylog", "inputcapture", "cliplogger"];
const KERBEROS_TOOLS = ["rubeus", "kerberoast", "asreproast", "golden ticket"];

export const credentialHarvestingDetector: Detector = {
  name: "CredentialHarvestingDetector",
  description: "Detects credential theft, dumping, brute force, and password attacks.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source !== "ENDPOINT" || !event.actor.process) return;
      const process = event.actor.process.toLowerCase();

      if (DUMPING_TOOLS.some((tool) => process.includes(tool))) {
        detections.push({
          detector: credentialHarvestingDetector.name,
          matchedEvents: [event],
          signals: ["credential_dumping", "lsass_access", "memory_scraping"],
          confidence: 0.95,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1003 - OS Credential Dumping"],
          reasoning: [
            `Credential dumping tool detected: ${event.actor.process}`,
            `User: ${event.actor.user}`,
          ],
        });
      }

      if (KEYLOGGERS.some((kl) => process.includes(kl))) {
        detections.push({
          detector: credentialHarvestingDetector.name,
          matchedEvents: [event],
          signals: ["keylogging", "input_capture"],
          confidence: 0.9,
          mitreTactics: ["Credential Access", "Collection"],
          mitreTechniques: ["T1056 - Input Capture"],
          reasoning: [`Keylogger detected: ${event.actor.process}`],
        });
      }

      if (KERBEROS_TOOLS.some((t) => process.includes(t))) {
        detections.push({
          detector: credentialHarvestingDetector.name,
          matchedEvents: [event],
          signals: ["kerberos_attack", "ticket_theft"],
          confidence: 0.95,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1558 - Steal or Forge Kerberos Tickets"],
          reasoning: [`Kerberos attack tool detected: ${event.actor.process}`],
        });
      }
    });

    const authEventsByIp = new Map<string, NormalizedEvent[]>();
    events
      .filter((e) => e.source === "AUTH" && e.network.sourceIp)
      .forEach((e) => {
        const list = authEventsByIp.get(e.network.sourceIp!) ?? [];
        list.push(e);
        authEventsByIp.set(e.network.sourceIp!, list);
      });

    authEventsByIp.forEach((ipEvents, sourceIp) => {
      const uniqueUsers = new Set(ipEvents.map((e) => e.actor.user).filter(Boolean));
      const failedAttempts = ipEvents.filter((e) => e.metadata?.result === "FAILED");

      if (uniqueUsers.size >= 5 && failedAttempts.length >= 5) {
        detections.push({
          detector: credentialHarvestingDetector.name,
          matchedEvents: ipEvents.slice(0, 10),
          signals: ["password_spraying", "credential_stuffing"],
          confidence: 0.85,
          mitreTactics: ["Credential Access"],
          mitreTechniques: ["T1110.003 - Password Spraying"],
          reasoning: [
            `Source IP ${sourceIp} attempted login to ${uniqueUsers.size} different accounts`,
            `${failedAttempts.length} failed attempts detected`,
          ],
        });
      }
    });

    return detections;
  },
};
