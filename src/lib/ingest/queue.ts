import type { IngestBatch, Integration, Prisma } from "@prisma/client";

import { jobGroups } from "@/lib/jobs/scheduler";
import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { parseBody } from "@/lib/integrations/mappers";
import { deadLetter, ingestForIntegration } from "@/lib/integrations/service";
import type { IngestFormat } from "@/lib/integrations/catalog";

// The durable queue between the ingest edge and the normalisers. The edge
// (POST /api/ingest/<id>, the forwarder, the pull collectors) only
// authenticates, stamps tenant and receive time, and stores the raw batch;
// workers claim batches with SKIP LOCKED (so any number can run), take
// tenants in turn so one noisy client can't starve the others, map, enrich
// and detect, retry a failed batch with backoff, and after the last attempt
// keep its payload in the dead-letter queue.
// Workers run in the web process unless HELIOS_INGEST_WORKER=external or
// HELIOS_JOBS leaves out "ingest", in which case the worker process
// (src/worker.ts) runs them on its own.

export const QUEUE = {
  // Batches waiting per client before the edge answers 429.
  maxPendingPerTenant: Number(process.env.HELIOS_INGEST_MAX_PENDING ?? 200),
  maxAttempts: 3,
  retryBaseMs: 30_000,
  // A batch "processing" this long belonged to a worker that died.
  staleAfterMs: 10 * 60_000,
  keepDoneDays: 7,
};

export type IngestChannel = "push" | "pull" | "forwarder";

export class QuotaError extends Error {
  constructor(
    message: string,
    readonly retryAfterSeconds: number,
  ) {
    super(message);
  }
}

export async function enqueueBatch(integration: Pick<Integration, "id" | "tenantId">, payload: string, opts: { channel: IngestChannel; stream?: string; format?: IngestFormat }) {
  const pending = await db.ingestBatch.count({ where: { tenantId: integration.tenantId, status: { in: ["QUEUED", "PROCESSING"] } } });
  if (pending >= QUEUE.maxPendingPerTenant) {
    throw new QuotaError(`${pending} batches are already waiting for this client; slow down and retry`, 30);
  }
  const batch = await db.ingestBatch.create({
    data: {
      tenantId: integration.tenantId,
      integrationId: integration.id,
      channel: opts.channel,
      stream: opts.stream,
      format: opts.format,
      payload,
      bytes: Buffer.byteLength(payload),
    },
  });
  kick();
  return batch;
}

// Tenants take turns: the one served longest ago goes next.
const lastServed = new Map<string, number>();
const tenantKey = (id: string | null) => id ?? "__soc__";

async function claimNext(): Promise<IngestBatch | null> {
  const waiting = await db.ingestBatch.findMany({ where: { status: "QUEUED", availableAt: { lte: new Date() } }, distinct: ["tenantId"], select: { tenantId: true } });
  const order = waiting.map((w) => w.tenantId).sort((a, b) => (lastServed.get(tenantKey(a)) ?? 0) - (lastServed.get(tenantKey(b)) ?? 0));
  for (const tenantId of order) {
    const rows = await db.$queryRaw<Array<{ id: string }>>`
      UPDATE ingest_batches SET status = 'PROCESSING', "startedAt" = now(), attempts = attempts + 1
      WHERE id = (
        SELECT id FROM ingest_batches
        WHERE status = 'QUEUED' AND "availableAt" <= now() AND "tenantId" IS NOT DISTINCT FROM ${tenantId}
        ORDER BY "receivedAt" LIMIT 1 FOR UPDATE SKIP LOCKED
      )
      RETURNING id`;
    if (rows[0]) {
      lastServed.set(tenantKey(tenantId), Date.now());
      return db.ingestBatch.findUnique({ where: { id: rows[0].id } });
    }
  }
  return null;
}

export async function processBatch(batch: IngestBatch) {
  const integration = await db.integration.findUnique({ where: { id: batch.integrationId } });
  const fail = async (error: string, keep: boolean) => {
    if (keep && integration) await deadLetter(integration, [{ raw: batch.payload, reason: error }], { batchId: batch.id, format: batch.format });
    await db.ingestBatch.update({ where: { id: batch.id }, data: { status: "FAILED", finishedAt: new Date(), error: error.slice(0, 1000), payload: "" } });
  };
  if (!integration) return fail("The integration was removed", false);
  if (!integration.enabled) return fail("The integration is disabled; replay from the dead-letter queue once it's enabled", true);
  try {
    const body = parseBody(batch.payload);
    const result = await ingestForIntegration(integration, body, { batchId: batch.id, format: (batch.format as IngestFormat | null) ?? undefined });
    await db.ingestBatch.update({ where: { id: batch.id }, data: { status: "DONE", finishedAt: new Date(), error: null, payload: "", result: result as unknown as Prisma.InputJsonValue } });
    if (result.received) await logAction({ action: "integration.ingest", detail: { integrationId: integration.id, batchId: batch.id, channel: batch.channel, stream: batch.stream, ...result } });
    return result;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (batch.attempts >= QUEUE.maxAttempts) {
      await fail(`Failed after ${batch.attempts} attempts: ${message}`, true);
      await db.integration.update({ where: { id: integration.id }, data: { status: "DEGRADED", lastError: `Ingest batch failed: ${message}`.slice(0, 500) } });
      return null;
    }
    await db.ingestBatch.update({ where: { id: batch.id }, data: { status: "QUEUED", error: message.slice(0, 1000), availableAt: new Date(Date.now() + QUEUE.retryBaseMs * 2 ** (batch.attempts - 1)) } });
    return null;
  }
}

let draining: Promise<number> | null = null;

// Works the queue until it's empty or the time budget is spent.
export function drainQueue(opts: { maxMs?: number; maxBatches?: number } = {}): Promise<number> {
  if (draining) return draining;
  draining = (async () => {
    const until = Date.now() + (opts.maxMs ?? 20_000);
    let done = 0;
    try {
      await db.ingestBatch.updateMany({ where: { status: "PROCESSING", startedAt: { lt: new Date(Date.now() - QUEUE.staleAfterMs) } }, data: { status: "QUEUED" } });
      while (Date.now() < until && done < (opts.maxBatches ?? 500)) {
        const batch = await claimNext();
        if (!batch) break;
        await processBatch(batch);
        done++;
      }
    } finally {
      draining = null;
    }
    return done;
  })();
  return draining;
}

export const workerInProcess = () => jobGroups(process.env.HELIOS_INGEST_WORKER === "external" ? ["core"] : ["core", "ingest"]).includes("ingest");

// Starts working right away after an enqueue, when workers run here.
export function kick() {
  if (!workerInProcess() || process.env.HELIOS_INGEST_KICK === "off") return;
  setImmediate(() => void drainQueue().catch((err) => console.error("ingest queue failed", err)));
}

// Finished batches are kept a week (the payload is already cleared).
export async function pruneBatches(now = new Date()) {
  const { count } = await db.ingestBatch.deleteMany({ where: { status: "DONE", finishedAt: { lt: new Date(now.getTime() - QUEUE.keepDoneDays * 86_400_000) } } });
  return count;
}

// A dead letter goes back on the queue as it was received.
export async function replayDeadLetters(ids: string[], actorId: string) {
  const letters = await db.ingestDeadLetter.findMany({ where: { id: { in: ids }, replayedAt: null }, include: { integration: { select: { id: true, tenantId: true } } } });
  const groups = new Map<string, typeof letters>();
  for (const l of letters) groups.set(`${l.integrationId}|${l.format ?? ""}`, [...(groups.get(`${l.integrationId}|${l.format ?? ""}`) ?? []), l]);
  for (const [, group] of groups) {
    const raws = group.map((l) => {
      try {
        return JSON.parse(l.raw) as unknown;
      } catch {
        return l.raw;
      }
    });
    // A whole failed batch is replayed as itself; single records as one list.
    const payload = group.length === 1 && typeof raws[0] === "string" ? (raws[0] as string) : JSON.stringify(raws.flat());
    await enqueueBatch(group[0].integration, payload, { channel: "push", format: (group[0].format as IngestFormat | null) ?? undefined });
  }
  await db.ingestDeadLetter.updateMany({ where: { id: { in: letters.map((l) => l.id) } }, data: { replayedAt: new Date(), replayedById: actorId } });
  await logAction({ actorId, action: "integration.dead_letters_replayed", detail: { count: letters.length } });
  return letters.length;
}
