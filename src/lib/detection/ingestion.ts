import { db } from "@/lib/db";
import type { EventSource, CaseSeverity } from "@prisma/client";

// Ported from signal-fusion's services/ingestion.ts + services/adapters/*
// (auth/endpoint/network/cloud) — collapsed into one file since each
// adapter was a small field-mapping function, not meaningfully distinct
// classes. Fixes a real bug found during the port: the network adapter
// only read `src_ip`/`dst_ip`, but the scenario fixtures (and the README's
// own curl example) send `source_ip`/`dest_ip` — silently dropping every
// simulated network event's IPs. This version accepts either.

export type RawLog = Record<string, unknown>;

interface NormalizedInput {
  timestamp: Date;
  eventType: string;
  actorUser?: string;
  actorProcess?: string;
  actorService?: string;
  sourceIp?: string;
  destIp?: string;
  geo?: string;
  severityHint: CaseSeverity;
  confidenceHint: number;
  metadata: Record<string, unknown>;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function normalize(source: EventSource, raw: RawLog): NormalizedInput {
  const timestamp = raw.timestamp ? new Date(raw.timestamp as string) : new Date();
  const base: NormalizedInput = {
    timestamp,
    eventType: "UNKNOWN",
    severityHint: "INFO",
    confidenceHint: 0.5,
    metadata: raw,
  };

  switch (source) {
    case "AUTH": {
      const failed = raw.result === "FAILED";
      return {
        ...base,
        eventType: failed ? "LOGIN_FAIL" : "LOGIN_SUCCESS",
        actorUser: str(raw.user) ?? str(raw.username) ?? "unknown",
        sourceIp: str(raw.source_ip) ?? str(raw.src_ip) ?? str(raw.ip),
        geo: str(raw.geo_location) ?? str(raw.geo),
        severityHint: failed ? "MEDIUM" : "INFO",
      };
    }
    case "ENDPOINT": {
      const suspicious = Boolean(raw.suspicious);
      return {
        ...base,
        eventType: str(raw.event_type) ?? "PROCESS_START",
        actorUser: str(raw.user),
        actorProcess: str(raw.process) ?? str(raw.process_name),
        severityHint: suspicious ? "HIGH" : "INFO",
        confidenceHint: suspicious ? 0.8 : 0.5,
        metadata: {
          ...raw,
          hostname: raw.hostname,
          parentProcess: raw.parent_process,
        },
      };
    }
    case "NETWORK": {
      return {
        ...base,
        eventType: str(raw.event_type) ?? "CONN_ESTABLISHED",
        sourceIp: str(raw.source_ip) ?? str(raw.src_ip),
        destIp: str(raw.dest_ip) ?? str(raw.dst_ip),
        metadata: {
          ...raw,
          port: raw.port,
          protocol: raw.protocol,
          bytes_transferred: raw.bytes_transferred ?? raw.bytesSent ?? 0,
        },
      };
    }
    case "CLOUD": {
      const denied = raw.status === "DENIED";
      return {
        ...base,
        eventType: str(raw.action) ?? "CLOUD_ACTION",
        actorUser: str(raw.user),
        actorService: str(raw.resource),
        severityHint: denied ? "MEDIUM" : "INFO",
        metadata: { ...raw, status: raw.status ?? "SUCCESS" },
      };
    }
  }
}

export async function ingestRawLog(source: EventSource, raw: RawLog) {
  const n = normalize(source, raw);
  return db.ingestedEvent.create({
    data: {
      source,
      eventType: n.eventType,
      timestamp: n.timestamp,
      actorUser: n.actorUser,
      actorProcess: n.actorProcess,
      actorService: n.actorService,
      sourceIp: n.sourceIp,
      destIp: n.destIp,
      geo: n.geo,
      severityHint: n.severityHint,
      confidenceHint: n.confidenceHint,
      metadata: n.metadata as never,
    },
  });
}

export async function ingestBatch(source: EventSource, rawLogs: RawLog[]) {
  const results = [];
  for (const log of rawLogs) results.push(await ingestRawLog(source, log));
  return results;
}
