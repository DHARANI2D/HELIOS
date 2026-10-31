import { db } from "@/lib/db";

// security_events is partitioned by month on "timestamp" (migration
// 20261031200000_partition_security_events). Queries go through the parent
// as before; Postgres reads only the months a time filter covers. A month
// gets its own table (security_events_YYYY_MM) ahead of time; anything
// outside them lands in security_events_default. A month past every
// client's retention, with no hold and no case evidence in it, is dropped
// whole instead of deleted row by row (lib/retention/service.ts).
//
// Each partition carries the parent's row-level policy too, so a tenant-
// scoped connection can't read a partition directly to get around it.

const PARENT = "security_events";
const DEFAULT = "security_events_default";
const NAME = /^security_events_\d{4}_\d{2}$/;
const LOCK = 727_201_031; // advisory lock: one partition change at a time

export interface EventPartition {
  name: string;
  from: Date;
  to: Date;
}

const monthStart = (d: Date) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
const addMonths = (d: Date, n: number) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1));
export const partitionName = (month: Date) => `${PARENT}_${month.getUTCFullYear()}_${String(month.getUTCMonth() + 1).padStart(2, "0")}`;
// Prisma stores DateTime as UTC in timestamp(3) columns.
const literal = (d: Date) => `'${d.toISOString().slice(0, 23).replace("T", " ")}'`;

const policy = (table: string) => [
  `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
  `ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY`,
  `CREATE POLICY tenant_isolation ON "${table}" USING (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true)) WITH CHECK (coalesce(current_setting('helios.tenant_id', true), '') = '' OR "tenantId" = current_setting('helios.tenant_id', true))`,
];

export async function eventsPartitioned() {
  const rows = await db.$queryRaw<Array<{ kind: string }>>`SELECT c.relkind::text AS kind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relname = ${PARENT} AND n.nspname = current_schema()`;
  return rows[0]?.kind === "p";
}

function parseBound(bound: string): { from: Date; to: Date } | null {
  const m = /FROM \('([^']+)'\) TO \('([^']+)'\)/.exec(bound);
  if (!m) return null;
  const at = (s: string) => new Date(`${s.replace(" ", "T")}Z`);
  return { from: at(m[1]), to: at(m[2]) };
}

// The monthly partitions, oldest first (the default partition isn't one).
export async function listPartitions(): Promise<EventPartition[]> {
  const rows = await db.$queryRaw<Array<{ name: string; bound: string }>>`
    SELECT c.relname AS name, pg_get_expr(c.relpartbound, c.oid) AS bound
    FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
    WHERE p.relname = ${PARENT}`;
  return rows
    .filter((r) => NAME.test(r.name))
    .flatMap((r) => {
      const b = parseBound(r.bound);
      return b ? [{ name: r.name, ...b }] : [];
    })
    .sort((a, b) => a.from.getTime() - b.from.getTime());
}

// Creates the month's partition if it isn't there. Rows for that month
// already sitting in the default partition move into it.
export async function ensureMonth(month: Date): Promise<boolean> {
  const from = monthStart(month);
  const to = addMonths(from, 1);
  const name = partitionName(from);
  return db.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${LOCK})`);
    const exists = await tx.$queryRaw<Array<{ n: number }>>`SELECT 1 AS n FROM pg_class WHERE relname = ${name}`;
    if (exists.length) return false;
    const range = `"timestamp" >= ${literal(from)} AND "timestamp" < ${literal(to)}`;
    const [{ stray }] = await tx.$queryRawUnsafe<Array<{ stray: boolean }>>(`SELECT EXISTS (SELECT 1 FROM "${DEFAULT}" WHERE ${range}) AS stray`);
    if (stray) {
      await tx.$executeRawUnsafe(`CREATE TABLE "${name}" (LIKE "${PARENT}" INCLUDING DEFAULTS)`);
      await tx.$executeRawUnsafe(`INSERT INTO "${name}" SELECT * FROM "${DEFAULT}" WHERE ${range}`);
      await tx.$executeRawUnsafe(`DELETE FROM "${DEFAULT}" WHERE ${range}`);
      await tx.$executeRawUnsafe(`ALTER TABLE "${PARENT}" ATTACH PARTITION "${name}" FOR VALUES FROM (${literal(from)}) TO (${literal(to)})`);
    } else {
      await tx.$executeRawUnsafe(`CREATE TABLE "${name}" PARTITION OF "${PARENT}" FOR VALUES FROM (${literal(from)}) TO (${literal(to)})`);
    }
    for (const sql of policy(name)) await tx.$executeRawUnsafe(sql);
    return true;
  });
}

// This month and the next `ahead`, so live events never land in the default
// partition. Run with the retention job.
export async function ensurePartitions(now = new Date(), ahead = 3) {
  if (!(await eventsPartitioned())) return { created: [] as string[] };
  const created: string[] = [];
  for (let i = 0; i <= ahead; i++) {
    const month = addMonths(monthStart(now), i);
    if (await ensureMonth(month)) created.push(partitionName(month));
  }
  return { created };
}

export async function partitionTenants(p: EventPartition) {
  const rows = await db.$queryRawUnsafe<Array<{ tenantId: string | null }>>(`SELECT DISTINCT "tenantId" FROM "${p.name}"`);
  return rows.map((r) => r.tenantId);
}

// Drops a month's partition, unless a case has taken any of its events
// meanwhile (checked under the table's lock, so none can be attached while
// it's checked). Returns how many events went with it, or null if kept.
export async function dropPartition(p: EventPartition): Promise<number | null> {
  if (!NAME.test(p.name)) throw new Error(`${p.name} isn't a monthly event partition`);
  return db.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${LOCK})`);
    await tx.$executeRawUnsafe(`LOCK TABLE "${p.name}" IN ACCESS EXCLUSIVE MODE`);
    const [{ evidence }] = await tx.$queryRawUnsafe<Array<{ evidence: boolean }>>(`SELECT EXISTS (SELECT 1 FROM "${p.name}" WHERE "caseId" IS NOT NULL) AS evidence`);
    if (evidence) return null;
    const [{ n }] = await tx.$queryRawUnsafe<Array<{ n: bigint }>>(`SELECT count(*) AS n FROM "${p.name}"`);
    await tx.$executeRawUnsafe(`ALTER TABLE "${PARENT}" DETACH PARTITION "${p.name}"`);
    await tx.$executeRawUnsafe(`DROP TABLE "${p.name}"`);
    return Number(n);
  });
}
