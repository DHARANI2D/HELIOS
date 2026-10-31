import { db } from "@/lib/db";

// security_events is partitioned by month on "timestamp" (migration
// 20261031200000_partition_security_events). Queries go through the parent
// as before; Postgres reads only the months a time filter covers. A month
// gets its own table (security_events_YYYY_MM) ahead of time; anything
// outside them lands in security_events_default. A month past every
// client's retention, with no hold and no case evidence in it, is dropped
// whole instead of deleted row by row (lib/retention/service.ts).
//
// Creating and dropping partitions is done by two database functions that
// run as the schema's owner (migration 20261031220000_partition_functions):
// the role the application signs in with can't create, alter or drop
// tables. Each new partition carries the parent's row-level policy, so a
// tenant-scoped connection can't read a partition directly to get around it.

const PARENT = "security_events";
const NAME = /^security_events_\d{4}_\d{2}$/;

export interface EventPartition {
  name: string;
  from: Date;
  to: Date;
}

const monthStart = (d: Date) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
const addMonths = (d: Date, n: number) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1));
export const partitionName = (month: Date) => `${PARENT}_${month.getUTCFullYear()}_${String(month.getUTCMonth() + 1).padStart(2, "0")}`;
// Prisma stores DateTime as UTC in timestamp(3) columns.
const literal = (d: Date) => d.toISOString().slice(0, 23).replace("T", " ");

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
  const [{ created }] = await db.$queryRaw<Array<{ created: boolean }>>`SELECT helios_ensure_event_partition(${literal(monthStart(month))}::timestamp) AS created`;
  return created;
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
  const [{ dropped }] = await db.$queryRaw<Array<{ dropped: bigint | null }>>`SELECT helios_drop_event_partition(${p.name}) AS dropped`;
  return dropped === null ? null : Number(dropped);
}
