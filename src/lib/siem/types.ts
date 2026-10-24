import type { DetectionSource } from "@prisma/client";
import type { IntelSnapshot } from "@/lib/threat-intel/local-intel";

// Ported from signal-fusion's backend/src/types.ts. UnifiedEvent is the
// in-memory shape detectors consume; it maps 1:1 onto the SecurityEvent table.

export type TelemetrySource = "auth" | "endpoint" | "network" | "cloud";
export type SeverityHint = "low" | "medium" | "high";

export interface UnifiedEvent {
  id: string;
  timestamp: Date;
  source: TelemetrySource;
  eventType: string;
  actor: { user?: string; process?: string; service?: string; host?: string };
  network: { sourceIp?: string; destIp?: string; destPort?: number; geo?: string };
  severityHint: SeverityHint;
  metadata: Record<string, unknown>;
}

export interface Detection {
  detector: string;
  detectionSource: DetectionSource;
  ruleId: string; // stable rule identifier within the detector
  matchedEvents: UnifiedEvent[];
  signals: string[];
  confidence: number; // 0-1
  reasoning: string[];
  mitreTactics: string[];
  mitreTechniques: string[];
}

export interface Detector {
  name: string;
  detectionSource: DetectionSource;
  description: string;
  // Techniques this detector can emit — feeds the "detectable" layer of the
  // MITRE coverage matrix.
  techniques: string[];
  run(events: UnifiedEvent[], ctx: DetectionContext): Detection[];
}

// What detectors may consult besides the events: the indicator store's
// knowledge about the IPs in this batch (see threat-intel/snapshot.ts).
export interface DetectionContext {
  intel: IntelSnapshot;
}

export interface ScoredDetection extends Detection {
  riskScore: number; // 0-1000, signal-fusion's enterprise risk scale
  riskObject: string;
  riskObjectType: "user" | "host" | "ip" | "unknown";
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  mitreTactics: string[];
  mitreTechniques: string[];
  severity: "Low" | "Medium" | "High";
  logs: ScenarioLog[];
}

export interface ScenarioLog {
  source: TelemetrySource;
  data: Record<string, unknown>;
  delayMs?: number;
}
