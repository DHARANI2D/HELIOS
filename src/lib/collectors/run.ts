import type { Integration, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { createHttp, type Http } from "@/lib/connectors/http";
import type { ConnectorCtx } from "@/lib/connectors/types";
import { readSecrets, type IntegrationConfig } from "@/lib/integrations/dispatch";
import { QuotaError, enqueueBatch } from "@/lib/ingest/queue";
import { collectorByKey, collectorForTool } from "@/lib/collectors/registry";
import type { Collector, CollectorStream } from "@/lib/collectors/types";

// Runs the pull collectors: every enabled stream of every enabled
// integration, when its checkpoint says it's due. Each page read is queued
// as a batch before the checkpoint moves (and before a queue message is
// deleted), so a crash re-reads rather than loses. Failures back off
// (doubling, up to 30 minutes); three in a row mark the integration degraded.

const MAX_PAGES = 10;
const MAX_BACKOFF_MS = 30 * 60_000;

export interface CollectorSetup {
  key: string;
  streams: string[];
  config?: Record<string, string>;
}

export const collectorSetup = (i: Pick<Integration, "config">) => ((i.config ?? {}) as IntegrationConfig & { collector?: CollectorSetup }).collector ?? null;

// Collector credentials share the integration's connector credentials where
// the field names match (one app registration for responding and reading).
export async function collectorContext(i: Pick<Integration, "id" | "config" | "secretCipher">, http: Http = createHttp()): Promise<ConnectorCtx> {
  const config = (i.config ?? {}) as IntegrationConfig & { collector?: CollectorSetup };
  const secrets = await readSecrets(i.secretCipher);
  return { config: { ...(config.connectorConfig ?? {}), ...(config.collector?.config ?? {}) }, secrets: { ...(secrets.connector ?? {}), ...(secrets.collector ?? {}) }, http, cacheKey: `${i.id}:collector` };
}

export function missingFields(collector: Collector, ctx: ConnectorCtx) {
  return collector.fields.filter((f) => f.required && !(f.secret ? ctx.secrets[f.key] : ctx.config[f.key])).map((f) => f.label);
}

export function enabledStreams(i: Pick<Integration, "config" | "vendor">): { collector: Collector; streams: CollectorStream[] } | null {
  const setup = collectorSetup(i);
  const collector = collectorByKey(setup?.key) ?? null;
  if (!setup || !collector || !collector.tools.includes(i.vendor)) return null;
  return { collector, streams: collector.streams.filter((s) => setup.streams.includes(s.key)) };
}

export interface PollSummary {
  stream: string;
  ok: boolean;
  records: number;
  pages: number;
  message: string;
}

export async function pollStream(integration: Integration, stream: CollectorStream, now = new Date(), http?: Http): Promise<PollSummary> {
  const key = { integrationId_stream: { integrationId: integration.id, stream: stream.key } };
  const checkpoint = await db.collectorCheckpoint.upsert({ where: key, update: {}, create: { integrationId: integration.id, stream: stream.key } });
  const ctx = await collectorContext(integration, http);
  let cursor = checkpoint.cursor;
  let records = 0;
  let pages = 0;
  let more = false;
  try {
    do {
      const page = await stream.poll(ctx, cursor, { now });
      if (page.records.length) await enqueueBatch(integration, JSON.stringify(page.records), { channel: "pull", stream: stream.key, format: stream.format });
      await page.commit?.();
      cursor = page.cursor;
      records += page.records.length;
      pages++;
      more = page.more;
      await db.collectorCheckpoint.update({ where: key, data: { cursor, lastPolledAt: new Date(), records: { increment: page.records.length } } });
    } while (more && pages < MAX_PAGES);
    await db.collectorCheckpoint.update({ where: key, data: { lastSuccessAt: new Date(), lastError: null, failures: 0, nextPollAt: new Date(Date.now() + (more ? 0 : stream.everyMs)) } });
    if (integration.status !== "CONNECTED" && records) await db.integration.update({ where: { id: integration.id }, data: { status: "CONNECTED", lastError: null } });
    return { stream: stream.key, ok: true, records, pages, message: records ? `Read ${records} record${records === 1 ? "" : "s"}` : "Nothing new" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // The client's queue is full: wait, without counting it against the source.
    if (err instanceof QuotaError) {
      await db.collectorCheckpoint.update({ where: key, data: { nextPollAt: new Date(Date.now() + err.retryAfterSeconds * 1000), lastError: message } });
      return { stream: stream.key, ok: false, records, pages, message };
    }
    const failures = checkpoint.failures + 1;
    await db.collectorCheckpoint.update({ where: key, data: { failures, lastError: message.slice(0, 500), lastPolledAt: new Date(), nextPollAt: new Date(Date.now() + Math.min(MAX_BACKOFF_MS, stream.everyMs * 2 ** failures)) } });
    if (failures >= 3) await db.integration.update({ where: { id: integration.id }, data: { status: "DEGRADED", lastError: `${stream.label}: ${message}`.slice(0, 500) } });
    return { stream: stream.key, ok: false, records, pages, message };
  }
}

// Every stream that is due, once. Instances race safely: a stream is
// claimed by moving its next poll time before it is polled.
export async function runDueCollectors(now = new Date(), http?: Http) {
  const integrations = await db.integration.findMany({ where: { enabled: true } });
  const results: PollSummary[] = [];
  for (const integration of integrations) {
    const setup = enabledStreams(integration);
    if (!setup?.streams.length) continue;
    if (missingFields(setup.collector, await collectorContext(integration)).length) continue;
    for (const stream of setup.streams) {
      const cp = await db.collectorCheckpoint.findUnique({ where: { integrationId_stream: { integrationId: integration.id, stream: stream.key } } });
      if (cp && cp.nextPollAt > now) continue;
      const claimed = await db.collectorCheckpoint.updateMany({
        where: { integrationId: integration.id, stream: stream.key, nextPollAt: cp?.nextPollAt ?? undefined },
        data: { nextPollAt: new Date(now.getTime() + 5 * 60_000) },
      });
      if (cp && !claimed.count) continue;
      results.push(await pollStream(integration, stream, now, http));
    }
  }
  return results;
}

// A read that changes nothing at the vendor, for the setup screen.
export async function testCollector(integration: Integration, setup: CollectorSetup, actorId: string, http?: Http) {
  const collector = collectorByKey(setup.key) ?? collectorForTool(integration.vendor);
  if (!collector) throw new Error("This tool has no log collector");
  const ctx = await collectorContext({ ...integration, config: { ...((integration.config ?? {}) as object), collector: setup } as unknown as Prisma.JsonValue }, http);
  const missing = missingFields(collector, ctx);
  if (missing.length) return [{ stream: "", ok: false, records: 0, pages: 0, message: `Set ${missing.join(", ")}` }];
  const out: PollSummary[] = [];
  for (const stream of collector.streams.filter((s) => setup.streams.includes(s.key))) {
    try {
      const page = await stream.poll(ctx, null, { now: new Date(), test: true });
      out.push({ stream: stream.key, ok: true, records: page.records.length, pages: 1, message: `${stream.label}: read ${page.records.length}${page.records.length >= 5 ? "+" : ""} from the last hour` });
    } catch (err) {
      out.push({ stream: stream.key, ok: false, records: 0, pages: 0, message: `${stream.label}: ${err instanceof Error ? err.message : String(err)}` });
    }
  }
  await logAction({ actorId, action: "collector.tested", detail: { integrationId: integration.id, collector: collector.key, results: out.map((r) => ({ stream: r.stream, ok: r.ok })) } });
  return out;
}
