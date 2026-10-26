import type { ConnectorCtx, ConnectorField } from "@/lib/connectors/types";
import type { IngestFormat } from "@/lib/integrations/catalog";

// Pull collectors: HELIOS polls a vendor's API for logs with the client's
// own read-only credentials. Every stream meets one contract:
//   poll(cursor) — fetch the next page after the checkpoint, returning the
//     raw records, the new checkpoint, whether another page is ready now,
//     and, for queues (SQS, Pub/Sub), commit() to delete or acknowledge what
//     was read once it is safely queued;
//   test — a poll that changes nothing at the vendor, to check access.
// Records go onto the ingest queue in the vendor's own shape and are mapped
// by the stream's format, so a re-poll is harmless: events are stored once
// per source event id, alerts once per vendor alert id.

export interface PollResult {
  records: unknown[];
  cursor: string | null;
  more: boolean;
  commit?: () => Promise<void>;
}

export interface PollOptions {
  now: Date;
  // A check: read, change nothing (no deletes, no acknowledgements).
  test?: boolean;
}

export interface CollectorStream {
  key: string; // "entra.signins"
  label: string;
  format: IngestFormat;
  // What the credential needs for this stream (and any licence).
  permissions: string;
  everyMs: number;
  // How far back the first poll reaches.
  initialLookbackMs: number;
  poll(ctx: ConnectorCtx, cursor: string | null, opts: PollOptions): Promise<PollResult>;
}

export interface Collector {
  key: string;
  label: string;
  // Catalog tools it collects from.
  tools: string[];
  // Credentials, named like the vendor's response connector's where there is one, so one app registration serves both.
  fields: ConnectorField[];
  // The documentation each call was written against; check it in a lab tenant before production.
  docs: string;
  streams: CollectorStream[];
}

export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
