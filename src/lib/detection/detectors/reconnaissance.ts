import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const reconnaissanceDetector: Detector = {
  name: "ReconnaissanceDetector",
  description: "Detects port scanning, DNS/network enumeration, OSINT gathering.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];
    const eventsBySource = new Map<string, NormalizedEvent[]>();

    events.forEach((e) => {
      const ip = e.network.sourceIp;
      if (!ip) return;
      const list = eventsBySource.get(ip) ?? [];
      list.push(e);
      eventsBySource.set(ip, list);
    });

    eventsBySource.forEach((sourceEvents, sourceIp) => {
      const networkEvents = sourceEvents.filter((e) => e.source === "NETWORK");
      const uniquePorts = new Set(
        networkEvents.map((e) => e.metadata?.port).filter((p) => p !== undefined),
      );

      if (uniquePorts.size >= 10) {
        detections.push({
          detector: reconnaissanceDetector.name,
          matchedEvents: networkEvents.slice(0, 10),
          signals: ["port_scanning", "network_reconnaissance"],
          confidence: 0.9,
          mitreTactics: ["Reconnaissance"],
          mitreTechniques: ["T1595 - Active Scanning"],
          reasoning: [
            `Source IP ${sourceIp} scanned ${uniquePorts.size} different ports`,
            "Indicates reconnaissance activity",
          ],
        });
      }

      const dnsQueries = sourceEvents.filter(
        (e) => e.source === "NETWORK" && e.metadata?.type === "DNS",
      );
      if (dnsQueries.length >= 50) {
        detections.push({
          detector: reconnaissanceDetector.name,
          matchedEvents: dnsQueries.slice(0, 20),
          signals: ["dns_enumeration", "network_mapping"],
          confidence: 0.85,
          mitreTactics: ["Reconnaissance"],
          mitreTechniques: ["T1590 - Gather Victim Network Information"],
          reasoning: [
            `Source IP ${sourceIp} performed ${dnsQueries.length} DNS queries`,
            "High volume DNS queries indicate network enumeration",
          ],
        });
      }
    });

    events.forEach((event) => {
      if (event.source === "NETWORK" && typeof event.metadata?.url === "string") {
        const url = event.metadata.url.toLowerCase();
        const osintSites = ["linkedin.com", "github.com", "pastebin.com", "shodan.io", "censys.io"];
        if (osintSites.some((site) => url.includes(site))) {
          detections.push({
            detector: reconnaissanceDetector.name,
            matchedEvents: [event],
            signals: ["osint_gathering", "information_collection"],
            confidence: 0.6,
            mitreTactics: ["Reconnaissance"],
            mitreTechniques: ["T1593 - Search Open Websites/Domains"],
            reasoning: [`Access to OSINT platform: ${event.metadata.url}`],
          });
        }
      }
    });

    events.forEach((event) => {
      if (event.source === "ENDPOINT" && event.actor.process) {
        const process = event.actor.process.toLowerCase();
        const infoCommands = ["systeminfo", "ipconfig", "hostname", "uname -a", "cat /etc/os-release"];
        if (infoCommands.some((cmd) => process.includes(cmd))) {
          detections.push({
            detector: reconnaissanceDetector.name,
            matchedEvents: [event],
            signals: ["system_enumeration", "host_discovery"],
            confidence: 0.7,
            mitreTactics: ["Discovery", "Reconnaissance"],
            mitreTechniques: ["T1082 - System Information Discovery"],
            reasoning: [
              `System information command executed: ${event.actor.process}`,
              `User: ${event.actor.user}`,
            ],
          });
        }
      }
    });

    return detections;
  },
};
