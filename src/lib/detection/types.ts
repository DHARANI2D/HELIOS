import type { EventSource, IngestedEvent } from "@prisma/client";

// Ported from signal-fusion's types.ts UnifiedEvent/Detector/Detection —
// the event shape detectors run against. `NormalizedEvent` is the
// in-memory shape (dates as Date, metadata parsed); IngestedEvent is the
// Prisma row it's read from.

export interface Actor {
  user?: string;
  process?: string;
  service?: string;
}

export interface Network {
  sourceIp?: string;
  destIp?: string;
  geo?: string;
}

export interface NormalizedEvent {
  id: string;
  timestamp: Date;
  source: EventSource;
  eventType: string;
  actor: Actor;
  network: Network;
  metadata: Record<string, unknown>;
}

export function toNormalizedEvent(row: IngestedEvent): NormalizedEvent {
  return {
    id: row.id,
    timestamp: row.timestamp,
    source: row.source,
    eventType: row.eventType,
    actor: {
      user: row.actorUser ?? undefined,
      process: row.actorProcess ?? undefined,
      service: row.actorService ?? undefined,
    },
    network: {
      sourceIp: row.sourceIp ?? undefined,
      destIp: row.destIp ?? undefined,
      geo: row.geo ?? undefined,
    },
    metadata: (row.metadata as Record<string, unknown>) ?? {},
  };
}

export interface DetectionResult {
  detector: string;
  matchedEvents: NormalizedEvent[];
  signals: string[];
  confidence: number;
  reasoning: string[];
  mitreTactics: string[];
  mitreTechniques: string[];
}

export interface Detector {
  name: string;
  description: string;
  run(events: NormalizedEvent[]): DetectionResult[];
}
