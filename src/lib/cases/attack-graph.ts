import type { CaseSeverity, CaseSource, CaseStatus, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { MAX_INDICATOR_FANOUT, usable } from "@/lib/cases/related";
import { TACTICS } from "@/lib/mitre/catalog";
import { severityRank } from "@/lib/severity";

// The attack graph: cases joined by the concrete things they share — hosts,
// accounts, IP addresses, indicators, AI agents. An entity is an attack
// chain when its cases, taken together, reach more ATT&CK tactics than any
// one of them does alone: the same box or account moving through the kill
// chain across alerts that were filed separately. (One broad case that
// already spans many tactics doesn't make everything it touches a chain.) Everything comes from case rows,
// linked telemetry and indicator links; nothing is inferred beyond that.

export type EntityType = "host" | "user" | "ip" | "domain" | "url" | "hash" | "email" | "agent";

export interface GraphCase {
  id: string;
  title: string;
  severity: CaseSeverity;
  status: CaseStatus;
  sourceType: CaseSource;
  createdAt: Date;
  tenantName: string | null;
  tactics: string[]; // tactic ids
}

export interface EntityLink {
  caseId: string;
  type: EntityType;
  value: string;
  malicious?: boolean;
}

export interface GraphEntity {
  key: string;
  type: EntityType;
  value: string;
  malicious: boolean;
  caseIds: string[];
}

export interface AttackChain {
  entity: GraphEntity;
  caseIds: string[]; // oldest first
  tactics: string[]; // kill-chain order
  severity: CaseSeverity;
  first: Date;
  last: Date;
}

export interface AttackGraph {
  cases: GraphCase[];
  entities: GraphEntity[];
  chains: AttackChain[];
  truncated: boolean;
}

const TACTIC_ORDER = new Map(TACTICS.map((t) => [t.id, t.order]));
const NOT_AN_ADDRESS = new Set(["0.0.0.0", "127.0.0.1", "::1", "255.255.255.255"]);

// Pure: given cases and what each one touches, keep the entities shared by
// at least `minShared` cases and find the chains among them.
export function assembleGraph(cases: GraphCase[], links: EntityLink[], minShared = 2): Omit<AttackGraph, "truncated"> {
  const byId = new Map(cases.map((c) => [c.id, c]));
  const entities = new Map<string, GraphEntity>();
  for (const l of links) {
    if (!byId.has(l.caseId)) continue;
    const value = l.value.trim();
    if (!usable(value) || (l.type === "ip" && NOT_AN_ADDRESS.has(value))) continue;
    const key = `${l.type}:${l.type === "host" || l.type === "user" || l.type === "email" || l.type === "domain" ? value.toLowerCase() : value}`;
    const e = entities.get(key) ?? { key, type: l.type, value, malicious: false, caseIds: [] };
    if (!e.caseIds.includes(l.caseId)) e.caseIds.push(l.caseId);
    e.malicious ||= !!l.malicious;
    entities.set(key, e);
  }
  const shared = [...entities.values()].filter((e) => e.caseIds.length >= minShared);

  const chains: AttackChain[] = [];
  for (const entity of shared) {
    const linked = entity.caseIds.map((id) => byId.get(id)!).sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    const tactics = [...new Set(linked.flatMap((c) => c.tactics))].sort((a, b) => (TACTIC_ORDER.get(a) ?? 99) - (TACTIC_ORDER.get(b) ?? 99));
    const widestCase = Math.max(...linked.map((c) => new Set(c.tactics).size));
    if (tactics.length < 2 || tactics.length <= widestCase) continue;
    chains.push({
      entity,
      caseIds: linked.map((c) => c.id),
      tactics,
      severity: linked.reduce<CaseSeverity>((max, c) => (severityRank(c.severity) > severityRank(max) ? c.severity : max), "INFO"),
      first: linked[0].createdAt,
      last: linked[linked.length - 1].createdAt,
    });
  }
  chains.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.tactics.length - a.tactics.length || b.caseIds.length - a.caseIds.length);

  const inGraph = new Set(shared.flatMap((e) => e.caseIds));
  return { cases: cases.filter((c) => inGraph.has(c.id)), entities: shared, chains };
}

const RISK_OBJECT: Record<string, EntityType> = { user: "user", host: "host", ip: "ip" };
const INDICATOR_TYPE: Record<string, EntityType> = { IP: "ip", DOMAIN: "domain", URL: "url", FILE_HASH: "hash", EMAIL_ADDRESS: "email" };

export async function loadAttackGraph(scope: Prisma.CaseWhereInput, since: Date, limit = 300): Promise<AttackGraph> {
  const rows = await db.case.findMany({
    where: { AND: [scope, { createdAt: { gte: since } }] },
    orderBy: { createdAt: "desc" },
    take: limit + 1,
    select: {
      id: true,
      title: true,
      severity: true,
      status: true,
      sourceType: true,
      sourceRef: true,
      createdAt: true,
      metadata: true,
      tenant: { select: { name: true } },
      mitreTechniques: { select: { technique: { select: { tacticId: true } } } },
    },
  });
  const truncated = rows.length > limit;
  const kept = rows.slice(0, limit);
  const ids = kept.map((c) => c.id);
  const cases: GraphCase[] = kept.map((c) => ({
    id: c.id,
    title: c.title,
    severity: c.severity,
    status: c.status,
    sourceType: c.sourceType,
    createdAt: c.createdAt,
    tenantName: c.tenant?.name ?? null,
    tactics: [...new Set(c.mitreTechniques.map((m) => m.technique.tacticId))],
  }));

  const links: EntityLink[] = [];
  for (const c of kept) {
    const meta = (c.metadata ?? {}) as Record<string, unknown>;
    if (typeof meta.hostName === "string") links.push({ caseId: c.id, type: "host", value: meta.hostName });
    if (typeof meta.userName === "string") links.push({ caseId: c.id, type: "user", value: meta.userName });
    if (c.sourceType === "SIEM_ALERT" && c.sourceRef?.includes(":")) {
      const [kind, ...rest] = c.sourceRef.split(":");
      if (RISK_OBJECT[kind]) links.push({ caseId: c.id, type: RISK_OBJECT[kind], value: rest.join(":") });
    }
    if (c.sourceType === "AGENT_GOVERNANCE" && c.sourceRef) links.push({ caseId: c.id, type: "agent", value: c.sourceRef });
  }

  const [hosts, users, sources, destinations, indicators] = await Promise.all([
    db.securityEvent.findMany({ where: { caseId: { in: ids }, hostName: { not: null } }, distinct: ["caseId", "hostName"], select: { caseId: true, hostName: true }, take: 20_000 }),
    db.securityEvent.findMany({ where: { caseId: { in: ids }, userName: { not: null } }, distinct: ["caseId", "userName"], select: { caseId: true, userName: true }, take: 20_000 }),
    db.securityEvent.findMany({ where: { caseId: { in: ids }, sourceIp: { not: null } }, distinct: ["caseId", "sourceIp"], select: { caseId: true, sourceIp: true }, take: 20_000 }),
    db.securityEvent.findMany({ where: { caseId: { in: ids }, destIp: { not: null } }, distinct: ["caseId", "destIp"], select: { caseId: true, destIp: true }, take: 20_000 }),
    db.caseIndicator.findMany({
      where: { caseId: { in: ids } },
      select: { caseId: true, indicator: { select: { type: true, value: true, maliciousScore: true, _count: { select: { caseLinks: true } } } } },
    }),
  ]);
  for (const e of hosts) links.push({ caseId: e.caseId!, type: "host", value: e.hostName! });
  for (const e of users) links.push({ caseId: e.caseId!, type: "user", value: e.userName! });
  for (const e of sources) links.push({ caseId: e.caseId!, type: "ip", value: e.sourceIp! });
  for (const e of destinations) links.push({ caseId: e.caseId!, type: "ip", value: e.destIp! });
  for (const ci of indicators) {
    const type = INDICATOR_TYPE[ci.indicator.type];
    // Seen everywhere (a CDN, a resolver) is infrastructure, not a lead.
    if (!type || ci.indicator._count.caseLinks > MAX_INDICATOR_FANOUT) continue;
    links.push({ caseId: ci.caseId, type, value: ci.indicator.value, malicious: (ci.indicator.maliciousScore ?? 0) >= 0.7 });
  }

  // Name governed agents rather than showing their ids.
  const agentIds = [...new Set(links.filter((l) => l.type === "agent").map((l) => l.value))];
  if (agentIds.length) {
    const names = new Map((await db.agent.findMany({ where: { id: { in: agentIds } }, select: { id: true, name: true } })).map((a) => [a.id, a.name]));
    for (const l of links) if (l.type === "agent") l.value = names.get(l.value) ?? l.value;
  }

  return { ...assembleGraph(cases, links), truncated };
}
