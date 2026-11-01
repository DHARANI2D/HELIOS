import { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { rawInScope } from "@/lib/tenant-db";
import { FIELDS, QueryError, bucketSeconds, parseQuery, type Query, type Term } from "@/lib/explore/query";

// Runs an Explore search: the matching events (newest first, a page at a
// time), how many there are, a histogram over the window, and the top
// values of the fields people pivot on. One transaction, a statement
// timeout, and for a client the same row-level scope as the rest of the
// portal. Column names come only from the fixed field list; every value is
// a bound parameter.

const COLUMNS = new Set(FIELDS.flatMap((f) => f.columns).concat(["id", "timestamp", "tenantId", "integrationId", "metadata", "ocsf"]));
const col = (c: string) => {
  if (!COLUMNS.has(c)) throw new Error(`Not a searchable column: ${c}`);
  return Prisma.raw(`"${c}"`);
};

// The columns free text looks in, plus the event's raw fields.
const TEXT_COLUMNS = ["hostName", "userName", "sourceIp", "destIp", "eventType", "processName", "parentProcessName", "commandLine", "filePath", "fileHash", "service", "source", "platform"];

// A * in a value matches anything; % and _ are literal.
export function likePattern(value: string, contains = false): string {
  const escaped = value.replace(/[\\%_]/g, (c) => `\\${c}`).replaceAll("*", "%");
  return contains && !value.includes("*") ? `%${escaped}%` : escaped;
}

const ts = (d: Date) => d.toISOString().slice(0, 23);

function termSql(t: Term): Prisma.Sql {
  let frag: Prisma.Sql;
  if (t.kind === "text") {
    const p = likePattern(t.value, true);
    frag = Prisma.sql`(${Prisma.join([...TEXT_COLUMNS.map((c) => Prisma.sql`${col(c)} ILIKE ${p}`), Prisma.sql`"metadata"::text ILIKE ${p}`, Prisma.sql`"ocsf"::text ILIKE ${p}`], " OR ")})`;
  } else if (t.op === "exists") {
    frag = Prisma.sql`(${Prisma.join(t.field.columns.map((c) => Prisma.sql`${col(c)} IS NOT NULL`), " OR ")})`;
  } else if (t.field.kind === "int") {
    const n = Number(t.values[0]);
    const ops = { eq: "=", gt: ">", gte: ">=", lt: "<", lte: "<=" } as const;
    const each = (c: string) =>
      t.op === "eq" ? Prisma.sql`${col(c)} IN (${Prisma.join(t.values.map(Number))})` : Prisma.sql`${col(c)} ${Prisma.raw(ops[t.op as keyof typeof ops])} ${n}`;
    frag = Prisma.sql`(${Prisma.join(t.field.columns.map(each), " OR ")})`;
  } else {
    frag = Prisma.sql`(${Prisma.join(t.field.columns.flatMap((c) => t.values.map((v) => Prisma.sql`${col(c)} ILIKE ${likePattern(v)}`)), " OR ")})`;
  }
  // An excluded value keeps the events that have no value at all.
  return t.negate ? Prisma.sql`NOT COALESCE(${frag}, false)` : frag;
}

export function whereSql(q: Query, scope: { tenantId: string | null }, from: Date, to: Date): Prisma.Sql {
  const parts: Prisma.Sql[] = [Prisma.sql`"timestamp" >= ${ts(from)}::timestamp`, Prisma.sql`"timestamp" <= ${ts(to)}::timestamp`];
  if (scope.tenantId) parts.push(Prisma.sql`"tenantId" = ${scope.tenantId}`);
  for (const group of q) parts.push(group.length === 1 ? termSql(group[0]) : Prisma.sql`(${Prisma.join(group.map(termSql), " OR ")})`);
  return Prisma.join(parts, " AND ");
}

// The fields shown as facets, in GROUPING SETS order.
export const FACETS = [
  { key: "host", column: "hostName", label: "Hosts" },
  { key: "user", column: "userName", label: "Accounts" },
  { key: "type", column: "eventType", label: "Event types" },
  { key: "src", column: "sourceIp", label: "Source IPs" },
  { key: "dst", column: "destIp", label: "Destination IPs" },
  { key: "port", column: "destPort", label: "Destination ports" },
  { key: "process", column: "processName", label: "Processes" },
  { key: "source", column: "source", label: "Log sources" },
  { key: "platform", column: "platform", label: "Products" },
  { key: "integration", column: "integrationId", label: "Client tools" },
  { key: "client", column: "tenantId", label: "Clients" },
] as const;
const FACET_TOP = 8;

export interface EventRow {
  id: string;
  timestamp: Date;
  source: string;
  platform: string | null;
  eventType: string;
  userName: string | null;
  hostName: string | null;
  processName: string | null;
  commandLine: string | null;
  sourceIp: string | null;
  destIp: string | null;
  destPort: number | null;
  filePath: string | null;
  fileHash: string | null;
  severityHint: string | null;
  classUid: number | null;
  tenantId: string | null;
  caseId: string | null;
  integrationId: string | null;
}

export interface SearchResult {
  rows: EventRow[];
  more: boolean;
  total: number;
  from: string;
  to: string;
  bucketSeconds: number;
  histogram: Array<{ t: string; n: number }>;
  facets: Array<{ key: string; label: string; values: Array<{ value: string; label: string; n: number }> }>;
  ms: number;
}

export interface SearchInput {
  q: string;
  from: Date;
  to: Date;
  // The client searched (null: every client, staff only).
  tenantId: string | null;
  // A client user's own tenant: the row-level scope for the transaction.
  rlsTenant: string | null;
  cursor?: { t: string; id: string } | null;
  limit?: number;
  facets?: boolean;
}

export async function searchEvents(input: SearchInput): Promise<SearchResult> {
  const started = Date.now();
  if (!(input.from < input.to)) throw new QueryError("The time range is empty");
  if (input.to.getTime() - input.from.getTime() > 400 * 86_400_000) throw new QueryError("Search at most 400 days at a time");
  const query = parseQuery(input.q);
  const where = whereSql(query, { tenantId: input.tenantId }, input.from, input.to);
  const limit = Math.min(Math.max(input.limit ?? 100, 1), 500);
  const cursor = input.cursor ? Prisma.sql` AND ("timestamp", "id") < (${input.cursor.t.slice(0, 23)}::timestamp, ${input.cursor.id})` : Prisma.empty;
  const secs = bucketSeconds(input.from.getTime(), input.to.getTime());
  const facets = input.facets !== false && !input.cursor ? FACETS.filter((f) => f.key !== "client" || !input.tenantId) : [];

  const queries: Prisma.PrismaPromise<unknown>[] = [
    db.$queryRaw`SELECT "id", "timestamp", "source", "platform", "eventType", "userName", "hostName", "processName", "commandLine", "sourceIp", "destIp", "destPort", "filePath", "fileHash", "severityHint", "classUid", "tenantId", "caseId", "integrationId"
      FROM security_events WHERE ${where}${cursor} ORDER BY "timestamp" DESC, "id" DESC LIMIT ${limit + 1}`,
  ];
  if (!input.cursor) {
    queries.push(db.$queryRaw`SELECT count(*)::int AS n FROM security_events WHERE ${where}`);
    queries.push(db.$queryRaw`SELECT date_bin(${secs} * interval '1 second', "timestamp", ${ts(input.from)}::timestamp) AS t, count(*)::int AS n FROM security_events WHERE ${where} GROUP BY 1 ORDER BY 1`);
  }
  if (facets.length) {
    const cols = facets.map((f) => col(f.column));
    queries.push(db.$queryRaw`
      SELECT g, v, n FROM (
        SELECT g, v, n, row_number() OVER (PARTITION BY g ORDER BY n DESC, v) AS rn FROM (
          SELECT GROUPING(${Prisma.join(cols)})::int AS g, COALESCE(${Prisma.join(cols.map((c) => Prisma.sql`${c}::text`))}) AS v, count(*)::int AS n
          FROM security_events WHERE ${where}
          GROUP BY GROUPING SETS (${Prisma.join(cols.map((c) => Prisma.sql`(${c})`))})
        ) a WHERE v IS NOT NULL
      ) b WHERE rn <= ${FACET_TOP}`);
  }

  let results: unknown[];
  try {
    results = await rawInScope(input.rlsTenant, queries);
  } catch (err) {
    if (String(err).includes("statement timeout")) throw new QueryError("The search took too long: narrow the time range or add a filter");
    throw err;
  }
  const rows = results[0] as EventRow[];
  const more = rows.length > limit;
  const page = rows.slice(0, limit);
  let total = page.length;
  let histogram: SearchResult["histogram"] = [];
  let i = 1;
  if (!input.cursor) {
    total = (results[i++] as Array<{ n: number }>)[0]?.n ?? 0;
    histogram = (results[i++] as Array<{ t: Date; n: number }>).map((b) => ({ t: new Date(b.t).toISOString(), n: b.n }));
  }

  const facetOut: SearchResult["facets"] = [];
  if (facets.length) {
    const raw = results[i] as Array<{ g: number; v: string; n: number }>;
    const all = (1 << facets.length) - 1;
    // Names for ids: the client's tools and the clients.
    const ids = (k: string) => raw.filter((r) => r.g === (all ^ (1 << (facets.length - 1 - facets.findIndex((f) => f.key === k))))).map((r) => r.v);
    const [integrations, tenants] = await Promise.all([
      facets.some((f) => f.key === "integration") ? db.integration.findMany({ where: { id: { in: ids("integration") } }, select: { id: true, name: true } }) : [],
      facets.some((f) => f.key === "client") ? db.tenant.findMany({ where: { id: { in: ids("client") } }, select: { id: true, name: true } }) : [],
    ]);
    const names = new Map<string, string>([...integrations.map((x) => [x.id, x.name] as const), ...tenants.map((x) => [x.id, x.name] as const)]);
    facets.forEach((f, k) => {
      const mask = all ^ (1 << (facets.length - 1 - k));
      const values = raw
        .filter((r) => r.g === mask)
        .sort((a, b) => b.n - a.n)
        .map((r) => ({ value: r.v, label: names.get(r.v) ?? r.v, n: r.n }));
      if (values.length) facetOut.push({ key: f.key, label: f.label, values });
    });
  }

  return { rows: page, more, total, from: input.from.toISOString(), to: input.to.toISOString(), bucketSeconds: secs, histogram, facets: facetOut, ms: Date.now() - started };
}

// Every event matching a search, for export (newest first, capped).
export async function exportEvents(input: Omit<SearchInput, "cursor" | "limit" | "facets">, cap = 10_000) {
  const query = parseQuery(input.q);
  const where = whereSql(query, { tenantId: input.tenantId }, input.from, input.to);
  const [rows] = await rawInScope(
    input.rlsTenant,
    [db.$queryRaw`SELECT "id", "timestamp", "source", "platform", "eventType", "userName", "hostName", "processName", "parentProcessName", "commandLine", "sourceIp", "destIp", "destPort", "filePath", "fileHash", "severityHint", "geo", "classUid", "tenantId", "caseId", "integrationId"
      FROM security_events WHERE ${where} ORDER BY "timestamp" DESC, "id" DESC LIMIT ${cap}`],
    { timeoutMs: 60_000 },
  );
  return rows as Array<EventRow & { parentProcessName: string | null; geo: string | null }>;
}
