import type { Detector, DetectionResult, NormalizedEvent } from "../types";

export const lateralMovementDetector: Detector = {
  name: "LateralMovementDetector",
  description: "Detects lateral movement via RDP, SMB, PsExec, WMI, Pass-the-Hash.",
  run(events: NormalizedEvent[]): DetectionResult[] {
    const detections: DetectionResult[] = [];

    events.forEach((event) => {
      if (event.source === "NETWORK" && event.metadata?.service === "RDP") {
        const sourceIp = event.network.sourceIp;
        const destIp = event.network.destIp;
        if (sourceIp?.startsWith("10.") && destIp?.startsWith("10.")) {
          detections.push({
            detector: lateralMovementDetector.name,
            matchedEvents: [event],
            signals: ["rdp_lateral_movement", "remote_access"],
            confidence: 0.75,
            mitreTactics: ["Lateral Movement"],
            mitreTechniques: ["T1021.001 - Remote Desktop Protocol"],
            reasoning: [`RDP connection from ${sourceIp} to ${destIp}`, `User: ${event.actor.user}`],
          });
        }
      }

      if (event.source === "NETWORK" && typeof event.metadata?.share === "string") {
        const share = event.metadata.share;
        if (["C$", "ADMIN$", "IPC$"].some((s) => share.includes(s))) {
          detections.push({
            detector: lateralMovementDetector.name,
            matchedEvents: [event],
            signals: ["admin_share_access", "smb_lateral_movement"],
            confidence: 0.8,
            mitreTactics: ["Lateral Movement"],
            mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares"],
            reasoning: [`Admin share access detected: ${share}`],
          });
        }
      }

      if (event.source === "ENDPOINT" && event.actor.process) {
        const process = event.actor.process.toLowerCase();

        if (process.includes("psexec") || process.includes("paexec")) {
          detections.push({
            detector: lateralMovementDetector.name,
            matchedEvents: [event],
            signals: ["psexec_execution", "remote_execution"],
            confidence: 0.9,
            mitreTactics: ["Lateral Movement", "Execution"],
            mitreTechniques: [
              "T1021.002 - SMB/Windows Admin Shares",
              "T1569.002 - Service Execution",
            ],
            reasoning: [`PsExec detected: ${event.actor.process}`],
          });
        }

        if (process.includes("wmic") && (process.includes("/node:") || process.includes("process call create"))) {
          detections.push({
            detector: lateralMovementDetector.name,
            matchedEvents: [event],
            signals: ["wmi_lateral_movement", "remote_wmi_execution"],
            confidence: 0.85,
            mitreTactics: ["Lateral Movement", "Execution"],
            mitreTechniques: ["T1047 - Windows Management Instrumentation"],
            reasoning: [`WMI remote execution: ${event.actor.process}`],
          });
        }
      }

      if (
        event.source === "AUTH" &&
        event.metadata?.auth_method === "NTLM" &&
        event.metadata?.anomaly === "hash_authentication"
      ) {
        detections.push({
          detector: lateralMovementDetector.name,
          matchedEvents: [event],
          signals: ["pass_the_hash", "ntlm_relay"],
          confidence: 0.9,
          mitreTactics: ["Lateral Movement", "Credential Access"],
          mitreTechniques: ["T1550.002 - Pass the Hash"],
          reasoning: [`NTLM hash authentication detected`, `Source: ${event.network.sourceIp}`],
        });
      }
    });

    return detections;
  },
};
