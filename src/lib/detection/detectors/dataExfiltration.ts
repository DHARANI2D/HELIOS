import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const dataExfiltrationDetector: Detector = {
  name: "DataExfiltrationDetector",
  description: "Detects large transfers, cloud uploads, DNS tunneling, automated exfiltration.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source === "NETWORK" && typeof event.metadata?.bytes_transferred === "number") {
        const bytes = event.metadata.bytes_transferred;
        if (bytes > 100 * 1024 * 1024) {
          detections.push({
            detector: dataExfiltrationDetector.name,
            matchedEvents: [event],
            signals: ["large_data_transfer", "potential_exfiltration"],
            confidence: 0.7,
            mitreTactics: ["Exfiltration"],
            mitreTechniques: ["T1048 - Exfiltration Over Alternative Protocol"],
            reasoning: [
              `Large data transfer detected: ${(bytes / 1024 / 1024).toFixed(2)} MB`,
              `From: ${event.network.sourceIp} To: ${event.network.destIp}`,
            ],
          });
        }
      }

      if (event.source === "CLOUD" && typeof event.metadata?.action === "string") {
        const action = event.metadata.action;
        const size = Number(event.metadata.size ?? 0);
        if (["S3_OBJECT_UPLOAD", "BLOB_UPLOAD", "DRIVE_UPLOAD"].includes(action) && size > 10 * 1024 * 1024) {
          detections.push({
            detector: dataExfiltrationDetector.name,
            matchedEvents: [event],
            signals: ["cloud_exfiltration", "unauthorized_upload"],
            confidence: 0.75,
            mitreTactics: ["Exfiltration"],
            mitreTechniques: ["T1567 - Exfiltration Over Web Service"],
            reasoning: [
              `Cloud upload detected: ${action}`,
              `Size: ${(size / 1024 / 1024).toFixed(2)} MB`,
              `User: ${event.actor.user}`,
            ],
          });
        }
      }
    });

    const dnsBySource = new Map<string, NormalizedEvent[]>();
    events
      .filter((e) => e.source === "NETWORK" && e.metadata?.type === "DNS" && e.network.sourceIp)
      .forEach((e) => {
        const list = dnsBySource.get(e.network.sourceIp!) ?? [];
        list.push(e);
        dnsBySource.set(e.network.sourceIp!, list);
      });

    dnsBySource.forEach((dnsEvents, sourceIp) => {
      const longQueries = dnsEvents.filter(
        (e) => typeof e.metadata?.query === "string" && (e.metadata.query as string).length > 50,
      );
      if (longQueries.length >= 10) {
        detections.push({
          detector: dataExfiltrationDetector.name,
          matchedEvents: longQueries.slice(0, 10),
          signals: ["dns_tunneling", "covert_channel"],
          confidence: 0.8,
          mitreTactics: ["Exfiltration", "Command and Control"],
          mitreTechniques: [
            "T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
          ],
          reasoning: [`${longQueries.length} unusually long DNS queries from ${sourceIp}`],
        });
      }
    });

    events.forEach((event) => {
      if (event.source === "ENDPOINT" && event.actor.process && typeof event.metadata?.parentProcess === "string") {
        const process = event.actor.process.toLowerCase();
        const parent = event.metadata.parentProcess.toLowerCase();
        if (
          (parent.includes("taskeng") || parent.includes("cron")) &&
          (process.includes("exfil") || process.includes("upload") || process.includes("ftp"))
        ) {
          detections.push({
            detector: dataExfiltrationDetector.name,
            matchedEvents: [event],
            signals: ["automated_exfiltration", "scheduled_upload"],
            confidence: 0.85,
            mitreTactics: ["Exfiltration"],
            mitreTechniques: ["T1020 - Automated Exfiltration"],
            reasoning: [`Scheduled exfiltration script: ${event.actor.process}`],
          });
        }
      }
    });

    return detections;
  },
};
