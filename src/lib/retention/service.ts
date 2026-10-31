import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { gunzipSync, gzipSync } from "node:zlib";
import type { LegalHold, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { openSealed, sealFor } from "@/lib/keys";
import { activeRulebook } from "@/lib/rulebook/service";
import { archiveStore, residency, type ArchiveStore } from "@/lib/retention/storage";
import { dropPartition, ensurePartitions, eventsPartitioned, listPartitions, partitionTenants } from "@/lib/retention/partitions";

// Log retention. Events stay searchable in the database for a client's hot
// period, then move to the archive store one UTC day at a time (compressed
// NDJSON, encrypted with a key of its own that is sealed with the client's
// data key), and are deleted when the retention period ends. Events on a
// case are kept with the case. Nothing a legal hold covers is ever deleted.
// CERT-In asks for logs kept for a rolling 180 days within Indian
// jurisdiction: where its rules apply, retention can't be set below 180
// days, and the page says whether the stores are in India.

const DAY = 86_400_000;
export const CERT_IN_DAYS = 180;
const PART_EVENTS = 20_000;
const PURGE_BATCH = 10_000;
const INTERNAL = { hotDays: 90, retentionDays: 365 };
const MAGIC = Buffer.from("HLA1");

const startOfDay = (d: Date) => new Date(Math.floor(d.getTime() / DAY) * DAY);
const dayKey = (d: Date) => d.toISOString().slice(0, 10);

// ---------------------------------------------------------------- rules

export async function retentionRules(tenantId: string | null) {
  if (!tenantId) return { ...INTERNAL, minDays: 30, certIn: false };
  const [tenant, book] = await Promise.all([db.tenant.findUniqueOrThrow({ where: { id: tenantId }, select: { logHotDays: true, logRetentionDays: true } }), activeRulebook(tenantId)]);
  const certIn = !!book?.body.obligations.regulatedEntity;
  return { hotDays: tenant.logHotDays, retentionDays: tenant.logRetentionDays, minDays: certIn ? CERT_IN_DAYS : 30, certIn };
}

export async function setRetention(tenantId: string, input: { hotDays: number; retentionDays: number }, actorId: string) {
  const { minDays, certIn, hotDays: wasHot, retentionDays: wasTotal } = await retentionRules(tenantId);
  const hot = Math.round(input.hotDays);
  const total = Math.round(input.retentionDays);
  if (!(hot >= 7 && hot <= 730)) throw new Error("Keep events searchable for between 7 and 730 days");
  if (!(total >= minDays && total <= 3650)) throw new Error(certIn ? `CERT-In's directions apply to this client: keep logs for at least ${CERT_IN_DAYS} days` : `Keep logs for between ${minDays} and 3650 days`);
  if (hot > total) throw new Error("The searchable period can't be longer than the whole retention");
  await db.tenant.update({ where: { id: tenantId }, data: { logHotDays: hot, logRetentionDays: total } });
  await logAction({ actorId, action: "retention.changed", detail: { tenantId, hotDays: hot, retentionDays: total, previous: { hotDays: wasHot, retentionDays: wasTotal } } });
}

// ---------------------------------------------------------------- holds

export async function placeHold(input: { tenantId: string; caseId?: string | null; reason: string; fromAt: Date; toAt?: Date | null }, actorId: string) {
  if (!input.reason.trim()) throw new Error("Say why the data is held (matter, request, reference)");
  if (input.toAt && input.toAt < input.fromAt) throw new Error("A hold has to end after it starts");
  if (input.caseId && !(await db.case.count({ where: { id: input.caseId, tenantId: input.tenantId } }))) throw new Error("That case isn't this client's");
  const hold = await db.legalHold.create({ data: { tenantId: input.tenantId, caseId: input.caseId || null, reason: input.reason.trim(), fromAt: input.fromAt, toAt: input.toAt ?? null, createdById: actorId } });
  await logAction({ actorId, caseId: hold.caseId ?? undefined, action: "retention.hold_placed", detail: { holdId: hold.id, tenantId: hold.tenantId, fromAt: hold.fromAt, toAt: hold.toAt, reason: hold.reason } });
  return hold;
}

export async function releaseHold(id: string, reason: string, actorId: string) {
  if (!reason.trim()) throw new Error("Say why the hold is released");
  const hold = await db.legalHold.findUniqueOrThrow({ where: { id } });
  if (hold.releasedAt) throw new Error("Already released");
  await db.legalHold.update({ where: { id }, data: { releasedAt: new Date(), releasedById: actorId, releaseReason: reason.trim() } });
  await logAction({ actorId, caseId: hold.caseId ?? undefined, action: "retention.hold_released", detail: { holdId: id, tenantId: hold.tenantId, reason } });
}

const activeHolds = (tenantId: string | null) => (tenantId ? db.legalHold.findMany({ where: { tenantId, releasedAt: null } }) : Promise.resolve([] as LegalHold[]));
export const heldBetween = (holds: Pick<LegalHold, "fromAt" | "toAt">[], from: Date, to: Date) => holds.some((h) => h.fromAt <= to && (!h.toAt || h.toAt >= from));

// ---------------------------------------------------------------- the archive format

const aadFor = (tenantId: string | null, day: Date, part: number) => `helios-archive:${tenantId ?? "internal"}:${dayKey(day)}:${part}`;

export async function packArchive(rows: unknown[], tenantId: string | null, day: Date, part: number) {
  const ndjson = Buffer.from(rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aadFor(tenantId, day, part)));
  const body = Buffer.concat([MAGIC, iv, Buffer.alloc(16), c.update(gzipSync(ndjson)), c.final()]);
  c.getAuthTag().copy(body, MAGIC.length + 12);
  return { body, sha256: createHash("sha256").update(body).digest("hex"), keySealed: await sealFor(tenantId, key.toString("base64")) };
}

export async function unpackArchive(body: Buffer, meta: { sha256: string; keySealed: string; tenantId: string | null; day: Date; part: number }) {
  if (createHash("sha256").update(body).digest("hex") !== meta.sha256) throw new Error("The archive object doesn't match its recorded hash: it was changed or damaged");
  if (!body.subarray(0, 4).equals(MAGIC)) throw new Error("Not a HELIOS archive object");
  const key = Buffer.from(await openSealed(meta.keySealed), "base64");
  const d = createDecipheriv("aes-256-gcm", key, body.subarray(4, 16));
  d.setAAD(Buffer.from(aadFor(meta.tenantId, meta.day, meta.part)));
  d.setAuthTag(body.subarray(16, 32));
  return Buffer.concat([d.update(body.subarray(32)), d.final()]);
}

// ---------------------------------------------------------------- the jobs

// One runner at a time across instances: a lease row with an expiry.
async function lease(name: string, ms: number) {
  const until = new Date(Date.now() + ms).toISOString();
  const rows = await db.$queryRaw<Array<{ key: string }>>`
    INSERT INTO platform_settings (key, value, "updatedAt") VALUES (${name}, ${JSON.stringify({ until })}::jsonb, now())
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, "updatedAt" = now()
    WHERE (platform_settings.value->>'until')::timestamptz < now()
    RETURNING key`;
  return rows.length > 0;
}
const unlease = (name: string) => db.$executeRaw`UPDATE platform_settings SET value = ${JSON.stringify({ until: new Date(0).toISOString() })}::jsonb WHERE key = ${name}`;

async function scopes() {
  const tenants = await db.tenant.findMany({ select: { id: true } });
  return [null, ...tenants.map((t) => t.id)];
}

const eventScope = (tenantId: string | null): Prisma.SecurityEventWhereInput => ({ tenantId, caseId: null });

// Moves events past their hot period into the archive, day by day.
export async function archiveDue(now = new Date(), budget = 200_000, store: ArchiveStore | null = archiveStore()) {
  if (!store) return { archived: 0, objects: 0, skipped: "no archive store configured" };
  if (!(await lease("retention.lease", 30 * 60_000))) return { archived: 0, objects: 0, skipped: "another worker is archiving" };
  let archived = 0;
  let objects = 0;
  try {
    for (const tenantId of await scopes()) {
      const { hotDays } = await retentionRules(tenantId);
      const cutoff = startOfDay(new Date(now.getTime() - hotDays * DAY));
      while (archived < budget) {
        const oldest = await db.securityEvent.findFirst({ where: { ...eventScope(tenantId), timestamp: { lt: cutoff } }, orderBy: { timestamp: "asc" }, select: { timestamp: true } });
        if (!oldest) break;
        const day = startOfDay(oldest.timestamp);
        const rows = await db.securityEvent.findMany({ where: { ...eventScope(tenantId), timestamp: { gte: day, lt: new Date(day.getTime() + DAY) } }, orderBy: [{ timestamp: "asc" }, { id: "asc" }], take: PART_EVENTS });
        const last = await db.eventArchive.findFirst({ where: { tenantId, day }, orderBy: { part: "desc" }, select: { part: true } });
        const part = (last?.part ?? 0) + 1;
        const packed = await packArchive(rows, tenantId, day, part);
        const objectKey = `${tenantId ?? "internal"}/${dayKey(day).replaceAll("-", "/")}/events-${part}.hla`;
        await store.put(objectKey, packed.body);
        await db.eventArchive.create({ data: { tenantId, day, part, storage: store.kind, objectKey, events: rows.length, bytes: packed.body.length, sha256: packed.sha256, keySealed: packed.keySealed, firstAt: rows[0].timestamp, lastAt: rows[rows.length - 1].timestamp } });
        // Only once the archive is recorded do the events leave the database.
        await db.securityEvent.deleteMany({ where: { id: { in: rows.map((r) => r.id) } } });
        archived += rows.length;
        objects++;
      }
    }
  } finally {
    await unlease("retention.lease");
  }
  if (objects) await logAction({ action: "retention.archived", detail: { events: archived, objects, store: store.describe } });
  return { archived, objects };
}

// Deletes what is past its retention, except what a hold covers.
export async function purgeDue(now = new Date(), store: ArchiveStore | null = archiveStore()) {
  let archives = 0;
  let events = 0;
  let held = 0;
  for (const tenantId of await scopes()) {
    const { retentionDays } = await retentionRules(tenantId);
    const cutoff = startOfDay(new Date(now.getTime() - retentionDays * DAY));
    const holds = await activeHolds(tenantId);
    const due = await db.eventArchive.findMany({ where: { tenantId, deletedAt: null, day: { lt: cutoff } }, take: 500 });
    for (const a of due) {
      if (heldBetween(holds, a.day, new Date(a.day.getTime() + DAY))) {
        held++;
        continue;
      }
      if (!store || store.kind !== a.storage) continue;
      await store.remove(a.objectKey);
      await db.eventArchive.update({ where: { id: a.id }, data: { deletedAt: now, deleteReason: `Past the ${retentionDays}-day retention` } });
      archives++;
    }
    // Events never archived (no store) that are past retention, in batches
    // so a long backlog doesn't become one huge delete.
    const keep: Prisma.SecurityEventWhereInput[] = holds.map((h) => ({ timestamp: { gte: h.fromAt, ...(h.toAt ? { lte: h.toAt } : {}) } }));
    const where: Prisma.SecurityEventWhereInput = { ...eventScope(tenantId), timestamp: { lt: cutoff }, ...(keep.length ? { NOT: { OR: keep } } : {}) };
    for (;;) {
      const batch = await db.securityEvent.findMany({ where, select: { id: true }, take: PURGE_BATCH });
      if (!batch.length) break;
      events += (await db.securityEvent.deleteMany({ where: { id: { in: batch.map((r) => r.id) } } })).count;
    }
  }
  if (archives || events) await logAction({ action: "retention.purged", detail: { archives, events, held } });
  return { archives, events, held };
}

// Whole months of events past every retention they're under: a month's
// partition goes in one statement instead of row by row, when every client
// with events in it is past its retention for the whole month, no hold
// covers any of it, and no case holds any of its events. The rest falls to
// purgeDue's batches as before.
export async function dropExpiredPartitions(now = new Date()) {
  if (!(await eventsPartitioned())) return { dropped: [] as string[], events: 0 };
  const dropped: string[] = [];
  let events = 0;
  const rules = new Map<string, { cutoff: Date; holds: LegalHold[] }>();
  const ruleFor = async (tenantId: string | null) => {
    const key = tenantId ?? "";
    if (!rules.has(key)) {
      const { retentionDays } = await retentionRules(tenantId);
      rules.set(key, { cutoff: startOfDay(new Date(now.getTime() - retentionDays * DAY)), holds: await activeHolds(tenantId) });
    }
    return rules.get(key)!;
  };
  for (const p of await listPartitions()) {
    if (p.to > now) break;
    const tenants = await partitionTenants(p);
    // An empty month goes once it's past the longest retention anyone has.
    const scope = tenants.length ? tenants : await scopes();
    let expired = true;
    for (const tenantId of scope) {
      const r = await ruleFor(tenantId);
      if (p.to > r.cutoff || (tenants.length && heldBetween(r.holds, p.from, p.to))) {
        expired = false;
        break;
      }
    }
    if (!expired) continue;
    const n = await dropPartition(p);
    if (n == null) continue;
    dropped.push(p.name);
    events += n;
    await logAction({ action: "retention.partition_dropped", detail: { partition: p.name, from: p.from.toISOString(), to: p.to.toISOString(), events: n, tenants: tenants.length } });
  }
  return { dropped, events };
}

export async function runRetention(now = new Date()) {
  const partitions = await ensurePartitions(now);
  const a = await archiveDue(now);
  const dropped = await dropExpiredPartitions(now);
  const p = await purgeDue(now);
  return { ...a, partitions: { ...partitions, ...dropped }, purged: p };
}

// ---------------------------------------------------------------- reading

export async function readArchive(id: string, actorId: string) {
  const a = await db.eventArchive.findUniqueOrThrow({ where: { id } });
  if (a.deletedAt) throw new Error("This archive was deleted when its retention ended");
  const store = archiveStore();
  if (!store || store.kind !== a.storage) throw new Error("The archive store it's in isn't configured here");
  const gz = await unpackArchive(await store.get(a.objectKey), a);
  await logAction({ actorId, action: "retention.archive_read", detail: { archiveId: id, tenantId: a.tenantId, day: dayKey(a.day), events: a.events } });
  return { filename: `${a.tenantId ?? "internal"}-${dayKey(a.day)}-${a.part}.ndjson.gz`, gz };
}

// Lines of one archive, for tests and tools.
export const archiveLines = (gz: Buffer) => gunzipSync(gz).toString("utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);

// ---------------------------------------------------------------- report

export async function retentionReport(now = new Date()) {
  const tenants = await db.tenant.findMany({ select: { id: true, name: true, isTest: true, logHotDays: true, logRetentionDays: true }, orderBy: { name: "asc" } });
  const rows = await Promise.all(
    tenants.map(async (t) => {
      const [rules, hot, oldest, onCases, archives, holds] = await Promise.all([
        retentionRules(t.id),
        db.securityEvent.count({ where: { tenantId: t.id } }),
        db.securityEvent.findFirst({ where: { tenantId: t.id }, orderBy: { timestamp: "asc" }, select: { timestamp: true } }),
        db.securityEvent.count({ where: { tenantId: t.id, caseId: { not: null } } }),
        db.eventArchive.aggregate({ where: { tenantId: t.id, deletedAt: null }, _count: true, _sum: { events: true, bytes: true }, _min: { day: true } }),
        db.legalHold.findMany({ where: { tenantId: t.id }, orderBy: { createdAt: "desc" } }),
      ]);
      // The oldest data kept, in the database or the archive.
      const earliest = [oldest?.timestamp, archives._min.day].filter((d): d is Date => !!d).sort((a, b) => a.getTime() - b.getTime())[0] ?? null;
      return {
        ...t,
        ...rules,
        hotEvents: hot,
        caseEvents: onCases,
        archives: archives._count,
        archivedEvents: archives._sum.events ?? 0,
        archivedBytes: archives._sum.bytes ?? 0,
        earliest,
        coveredDays: earliest ? Math.floor((now.getTime() - earliest.getTime()) / DAY) : 0,
        holds,
      };
    }),
  );
  return { ...residency(), tenants: rows };
}
