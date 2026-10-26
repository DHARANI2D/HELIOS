import type { Prisma } from "@prisma/client";

import type { SeverityHint, TelemetrySource, UnifiedEvent } from "@/lib/siem/types";
import { rowFromColumns } from "@/lib/ocsf/rows";

// Ported from signal-fusion's services/adapters/{auth,endpoint,network,cloud}
// Adapter. Each normalizes one raw vendor-ish log into the UnifiedEvent shape.
// Field aliases are deliberately generous: the original NetworkAdapter only
// read src_ip/dst_ip, silently dropping the source_ip/dest_ip spelling its
// own attack scenarios used.

type Raw = Record<string, unknown>;
export type NormalizedEvent = Omit<UnifiedEvent, "id">;

function str(...values: unknown[]): string | undefined {
  for (const v of values) {
    if (typeof v === "string" && v.trim()) return v.trim();
    if (typeof v === "number") return String(v);
  }
  return undefined;
}

function num(...values: unknown[]): number | undefined {
  for (const v of values) {
    const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function timestampOf(raw: Raw): Date {
  const value = raw.timestamp ?? raw["@timestamp"] ?? raw.time;
  const d = value ? new Date(value as string) : new Date();
  return Number.isNaN(d.getTime()) ? new Date() : d;
}

function base(source: TelemetrySource, raw: Raw, eventType: string, severityHint: SeverityHint = "low"): NormalizedEvent {
  return {
    timestamp: timestampOf(raw),
    source,
    eventType,
    actor: {},
    network: {},
    severityHint,
    metadata: { ...raw },
  };
}

function normalizeAuth(raw: Raw): NormalizedEvent {
  const failed = String(raw.result ?? raw.status ?? "").toUpperCase() === "FAILED";
  const event = base("auth", raw, failed ? "LOGIN_FAIL" : "LOGIN_SUCCESS", failed ? "medium" : "low");
  event.actor = { user: str(raw.user, raw.username, raw.target_user) ?? "unknown", host: str(raw.hostname, raw.host) };
  event.network = { sourceIp: str(raw.source_ip, raw.src_ip, raw.ip), geo: str(raw.geo_location, raw.geo, raw.country) };
  return event;
}

function normalizeEndpoint(raw: Raw): NormalizedEvent {
  const event = base("endpoint", raw, str(raw.event_type) ?? "PROCESS_START", raw.suspicious ? "high" : "low");
  event.actor = {
    user: str(raw.user, raw.username),
    process: str(raw.process, raw.process_name, raw.command_line, raw.commandline),
    host: str(raw.hostname, raw.host, raw.computer_name),
  };
  event.network = { sourceIp: str(raw.source_ip, raw.src_ip), destIp: str(raw.dest_ip, raw.dst_ip) };
  event.metadata = { ...raw, parentProcess: str(raw.parent_process, raw.parent_process_name), hash: str(raw.hash, raw.sha256) };
  return event;
}

function normalizeNetwork(raw: Raw): NormalizedEvent {
  const event = base("network", raw, str(raw.event_type) ?? "CONN_ESTABLISHED");
  event.actor = { user: str(raw.user), host: str(raw.hostname, raw.host) };
  event.network = {
    sourceIp: str(raw.source_ip, raw.src_ip),
    destIp: str(raw.dest_ip, raw.dst_ip),
    destPort: num(raw.port, raw.dest_port, raw.dst_port),
  };
  event.metadata = { ...raw, port: num(raw.port, raw.dest_port, raw.dst_port), protocol: str(raw.protocol) };
  return event;
}

function normalizeCloud(raw: Raw): NormalizedEvent {
  const denied = String(raw.status ?? "").toUpperCase() === "DENIED";
  const event = base("cloud", raw, str(raw.action) ?? "CLOUD_ACTION", denied ? "medium" : "low");
  event.actor = { user: str(raw.user, raw.principal), service: str(raw.resource, raw.service) };
  event.network = { sourceIp: str(raw.source_ip, raw.src_ip) };
  event.metadata = { ...raw, status: str(raw.status) ?? "SUCCESS" };
  return event;
}

export const TELEMETRY_SOURCES: TelemetrySource[] = ["auth", "endpoint", "network", "cloud"];

export function isTelemetrySource(value: unknown): value is TelemetrySource {
  return typeof value === "string" && (TELEMETRY_SOURCES as string[]).includes(value);
}

export function normalize(source: TelemetrySource, raw: Raw): NormalizedEvent {
  switch (source) {
    case "auth":
      return normalizeAuth(raw);
    case "endpoint":
      return normalizeEndpoint(raw);
    case "network":
      return normalizeNetwork(raw);
    case "cloud":
      return normalizeCloud(raw);
  }
}

// UnifiedEvent <-> SecurityEvent row mapping. The row carries the event's
// OCSF form too (lib/ocsf).
export function toEventRow(event: NormalizedEvent, batchId: string, sourceEventId?: string): Prisma.SecurityEventCreateManyInput {
  return rowFromColumns(
    {
      timestamp: event.timestamp,
      source: event.source,
      platform: "signal-fusion",
      eventType: event.eventType,
      userName: event.actor.user,
      hostName: event.actor.host,
      service: event.actor.service,
      processName: event.actor.process,
      commandLine: event.actor.process,
      parentProcessName: (event.metadata.parentProcess as string | undefined) ?? undefined,
      sourceIp: event.network.sourceIp,
      destIp: event.network.destIp,
      destPort: event.network.destPort,
      geo: event.network.geo,
      fileHash: (event.metadata.hash as string | undefined) ?? undefined,
      severityHint: event.severityHint,
      metadata: event.metadata,
    },
    { batchId },
    sourceEventId,
  );
}

export function fromEventRow(row: {
  id: string;
  timestamp: Date;
  source: string;
  eventType: string;
  userName: string | null;
  hostName: string | null;
  service: string | null;
  processName: string | null;
  commandLine?: string | null;
  sourceIp: string | null;
  destIp: string | null;
  destPort: number | null;
  geo: string | null;
  severityHint: string | null;
  metadata: Prisma.JsonValue;
}): UnifiedEvent {
  return {
    id: row.id,
    timestamp: row.timestamp,
    source: (isTelemetrySource(row.source) ? row.source : "endpoint") as TelemetrySource,
    eventType: row.eventType,
    actor: {
      user: row.userName ?? undefined,
      // Detectors match on the command line where there is one.
      process: row.commandLine ?? row.processName ?? undefined,
      service: row.service ?? undefined,
      host: row.hostName ?? undefined,
    },
    network: {
      sourceIp: row.sourceIp ?? undefined,
      destIp: row.destIp ?? undefined,
      destPort: row.destPort ?? undefined,
      geo: row.geo ?? undefined,
    },
    severityHint: (row.severityHint as SeverityHint | null) ?? "low",
    metadata: row.metadata && typeof row.metadata === "object" && !Array.isArray(row.metadata) ? (row.metadata as Record<string, unknown>) : {},
  };
}
