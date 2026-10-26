import { ConnectorError } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import type { PollResult } from "@/lib/collectors/types";

// Time-window polling for APIs that filter by "since" and page with a next
// link or token. The checkpoint is the newest record time seen; each poll
// reaches back `overlapMs` before it, because logs arrive late, and the
// overlap's repeats are dropped at storage (source event ids).

export interface SinceCursor {
  since: string;
  // Mid-way through a listing: the next page and the newest time seen so far.
  next?: string;
  maxSeen?: string;
}

export function readCursor(cursor: string | null, now: Date, lookbackMs: number): SinceCursor {
  if (cursor) {
    try {
      const c = JSON.parse(cursor) as SinceCursor;
      if (c.since && !Number.isNaN(Date.parse(c.since))) return c;
    } catch {
      // fall through to a fresh start
    }
  }
  return { since: new Date(now.getTime() - lookbackMs).toISOString() };
}

const later = (a: string | undefined, b: string | undefined) => (!a ? b : !b ? a : Date.parse(a) >= Date.parse(b) ? a : b);

export interface SincePage {
  records: unknown[];
  next?: string;
  times: Array<string | undefined>;
}

// One page: the first (from `since` minus the overlap) or the next one.
export async function pollSince(
  cursor: string | null,
  opts: { now: Date; lookbackMs: number; overlapMs: number },
  fetchPage: (c: { since: string; next?: string }) => Promise<SincePage>,
): Promise<PollResult> {
  const c = readCursor(cursor, opts.now, opts.lookbackMs);
  const since = new Date(Date.parse(c.since) - opts.overlapMs).toISOString();
  const page = await fetchPage({ since, next: c.next });
  const maxSeen = page.times.reduce<string | undefined>((m, t) => later(m, t), c.maxSeen);
  if (page.next) return { records: page.records, cursor: JSON.stringify({ since: c.since, next: page.next, maxSeen }), more: true };
  return { records: page.records, cursor: JSON.stringify({ since: later(c.since, maxSeen) }), more: false };
}

// A next link must stay on the vendor's own host: it is followed with the client's credential.
export function sameHost(link: string, base: string) {
  const a = new URL(link);
  const b = new URL(base);
  if (a.protocol !== "https:" || a.host !== b.host) throw new ConnectorError(`Refusing to follow a next link to ${a.host}`, null);
  return link;
}

export const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

export type { ConnectorCtx };
