import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { gatherEvidence, type CaseEntities } from "@/lib/ai/evidence";

// The evidence sweep: before HELIOS investigates a case on its own, it
// collects every log the client's own tools hold about it. Each client has
// different tools, so the sweep works from that client's integrations:
//   1. catch up now with each of its log sources (pull collectors), and work
//      the ingest queue so what they return is stored;
//   2. gather every event touching the case's hosts, accounts, addresses,
//      files and processes, from shortly before the activity to now, and
//      group them by log type (endpoint, identity, network, email, cloud,
//      tool alerts);
//   3. attach them to the case as evidence (kept as long as the case);
//   4. say which log types the case needed that the client doesn't send,
//      so the report and the reviewer know what HELIOS couldn't see.

export const LOG_TYPES = {
  endpoint: "Endpoint (process, file)",
  identity: "Identity (sign-ins, accounts)",
  network: "Network (connections, DNS, web)",
  email: "Email",
  cloud: "Cloud and SaaS (API activity)",
  alerts: "Security tool alerts",
  other: "Other",
} as const;
export type LogType = keyof typeof LOG_TYPES;

// Which of the client's tool categories can send each log type.
const CATEGORY_LOGS: Record<string, LogType[]> = {
  edr: ["endpoint", "alerts"], epp: ["endpoint", "alerts"], mdm: ["endpoint"], mtd: ["endpoint", "alerts"], dlp: ["endpoint", "alerts"], vuln: ["endpoint"],
  identity: ["identity", "alerts"], pam: ["identity"],
  email: ["email", "alerts"],
  network: ["network", "alerts"], ndr: ["network", "alerts"], ot: ["network", "alerts"], netmgmt: ["network"],
  cloud: ["cloud", "alerts"], webapp: ["cloud", "network", "alerts"], code: ["cloud"],
  siem: ["endpoint", "identity", "network", "email", "cloud", "alerts"],
};

export function logTypeOf(e: { classUid: number | null; source: string }): LogType {
  const c = e.classUid ?? 0;
  if (c === 1001 || c === 1007 || ["endpoint", "process", "file", "registry"].includes(e.source)) return "endpoint";
  if (c === 3001 || c === 3002 || e.source === "auth" || e.source === "identity") return "identity";
  if (c === 4001 || c === 4002 || c === 4003 || ["network", "dns", "proxy", "firewall"].includes(e.source)) return "network";
  if (e.source === "email" || e.source === "mail") return "email";
  if (c === 6003 || e.source === "cloud" || e.source === "saas") return "cloud";
  if (c === 2004 || e.source === "alert") return "alerts";
  return "other";
}

// The log types a case needs, from what it involves.
export function neededLogTypes(entities: CaseEntities, domain: string | null): LogType[] {
  const need = new Set<LogType>(["alerts"]);
  if (entities.hosts.length || entities.processes.length || entities.hashes.length) need.add("endpoint");
  if (entities.users.length) need.add("identity");
  if (entities.ips.length || entities.domains.length) need.add("network");
  if (entities.emails.length || domain === "EMAIL") need.add("email");
  if (domain === "CLOUD") need.add("cloud");
  if (domain === "IDENTITY") need.add("identity");
  if (domain === "NETWORK") need.add("network");
  if (domain === "ENDPOINT") need.add("endpoint");
  return [...need];
}

export interface SweepLogType {
  type: LogType;
  label: string;
  needed: boolean;
  // The client's tools that can send it.
  sources: string[];
  events: number;
  first: string | null;
  last: string | null;
}

export interface EvidenceSweep {
  window: { from: string; to: string };
  entities: { hosts: number; users: number; ips: number; hashes: number; processes: number; emails: number };
  refreshed: Array<{ source: string; stream: string; ok: boolean; records: number; message: string }>;
  logTypes: SweepLogType[];
  gaps: Array<{ type: LogType; label: string; why: string }>;
  events: number;
  attached: number;
}

const ATTACH_CAP = 1000;
const BEFORE_MS = 24 * 3_600_000;

export async function sweepEvidence(caseId: string, opts: { now?: Date; refresh?: boolean } = {}): Promise<EvidenceSweep> {
  const now = opts.now ?? new Date();
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { tenantId: true, domain: true, createdAt: true } });
  const evidence = await gatherEvidence(caseId);
  const ent = evidence.entities;

  // 1. Catch up with the client's own sources, and store what they return.
  const refreshed: EvidenceSweep["refreshed"] = [];
  if (kase.tenantId && opts.refresh !== false) {
    const { pollTenantNow } = await import("@/lib/collectors/run");
    for (const r of await pollTenantNow(kase.tenantId, now).catch(() => [])) refreshed.push({ source: r.integration, stream: r.stream, ok: r.ok, records: r.records, message: r.message });
    if (refreshed.some((r) => r.records > 0)) {
      const { drainQueue } = await import("@/lib/ingest/queue");
      await drainQueue({ maxMs: 30_000 }).catch(() => 0);
    }
  }

  // 2. Every event that touches the case, from a day before it began to now.
  const first = await db.securityEvent.findFirst({ where: { caseId }, orderBy: { timestamp: "asc" }, select: { timestamp: true } });
  const from = new Date((first?.timestamp ?? kase.createdAt).getTime() - BEFORE_MS);
  const any = (field: string, values: string[]) => (values.length ? [{ [field]: { in: values.slice(0, 200), mode: "insensitive" } } as Prisma.SecurityEventWhereInput] : []);
  const touches: Prisma.SecurityEventWhereInput[] = [
    ...any("hostName", ent.hosts),
    ...any("userName", ent.users),
    ...any("sourceIp", ent.ips),
    ...any("destIp", ent.ips),
    ...(ent.hashes.length ? [{ fileHash: { in: ent.hashes.slice(0, 200) } }] : []),
    ...any("processName", ent.processes),
  ];
  const where: Prisma.SecurityEventWhereInput | null = touches.length ? { tenantId: kase.tenantId, timestamp: { gte: from, lte: now }, OR: touches } : null;
  const groups = where
    ? await db.securityEvent.groupBy({ by: ["classUid", "source", "integrationId"], where, _count: { _all: true }, _min: { timestamp: true }, _max: { timestamp: true } })
    : [];

  // 3. Attach them to the case, most recent first, up to the cap.
  let attached = 0;
  if (where) {
    const ids = await db.securityEvent.findMany({ where: { ...where, caseId: null }, orderBy: { timestamp: "desc" }, take: ATTACH_CAP, select: { id: true, timestamp: true } });
    if (ids.length) {
      const res = await db.securityEvent.updateMany({ where: { id: { in: ids.map((i) => i.id) }, timestamp: { gte: from, lte: now }, caseId: null }, data: { caseId } });
      attached = res.count;
    }
  }

  // 4. What each log type holds, which of the client's tools send it, and the gaps.
  const integrations = kase.tenantId ? await db.integration.findMany({ where: { tenantId: kase.tenantId, enabled: true }, select: { name: true, category: true } }) : [];
  const needed = neededLogTypes(ent, kase.domain);
  const types = (Object.keys(LOG_TYPES) as LogType[]).filter((t) => t !== "other" || groups.some((g) => logTypeOf({ classUid: g.classUid, source: g.source }) === "other"));
  const logTypes: SweepLogType[] = types.map((type) => {
    const gs = groups.filter((g) => logTypeOf({ classUid: g.classUid, source: g.source }) === type);
    const firsts = gs.map((g) => g._min.timestamp).filter(Boolean) as Date[];
    const lasts = gs.map((g) => g._max.timestamp).filter(Boolean) as Date[];
    return {
      type,
      label: LOG_TYPES[type],
      needed: needed.includes(type),
      sources: integrations.filter((i) => (CATEGORY_LOGS[i.category] ?? []).includes(type)).map((i) => i.name),
      events: gs.reduce((n, g) => n + g._count._all, 0),
      first: firsts.length ? new Date(Math.min(...firsts.map((d) => d.getTime()))).toISOString() : null,
      last: lasts.length ? new Date(Math.max(...lasts.map((d) => d.getTime()))).toISOString() : null,
    };
  });
  const gaps = logTypes
    .filter((t) => t.needed && t.type !== "alerts" && t.sources.length === 0 && t.events === 0)
    .map((t) => ({ type: t.type, label: t.label, why: `The client has no ${t.label.toLowerCase()} source connected, so HELIOS couldn't see that side of this case` }));

  return {
    window: { from: from.toISOString(), to: now.toISOString() },
    entities: { hosts: ent.hosts.length, users: ent.users.length, ips: ent.ips.length, hashes: ent.hashes.length, processes: ent.processes.length, emails: ent.emails.length },
    refreshed,
    logTypes,
    gaps,
    events: logTypes.reduce((n, t) => n + t.events, 0),
    attached,
  };
}
