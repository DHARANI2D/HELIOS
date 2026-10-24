import type { CaseSeverity, CaseSource, CaseStatus, IndicatorType } from "@prisma/client";

import { db } from "@/lib/db";

// Related-case memory. Replaces asip's Qdrant "similar past incidents"
// vector store with something analysts can audit: prior cases that share
// concrete evidence — the same IOCs, the same hosts or accounts, the same AI
// agent — ranked by how much they share. ATT&CK overlap only adds weight; on
// its own it's too common (half of all cases involve T1059) to mean much.

export interface RelatedCase {
  id: string;
  title: string;
  sourceType: CaseSource;
  severity: CaseSeverity;
  status: CaseStatus;
  verdict: string | null;
  rootCauseNarrative: string | null;
  createdAt: Date;
  score: number;
  reasons: string[];
}

// Accounts/hosts too generic to link cases (every Windows box has SYSTEM).
const ENTITY_STOPLIST = new Set([
  "", "-", "n/a", "unknown", "unknown_host", "system", "nt authority\\system", "local service", "network service",
  "nt authority\\local service", "nt authority\\network service", "root", "www-data", "localhost",
]);
// An indicator seen in this many cases is infrastructure noise, not a lead.
const MAX_INDICATOR_FANOUT = 50;
const WEIGHT = { maliciousIndicator: 3, indicator: 2, entity: 2, agent: 3, technique: 1 };
const MAX_TECHNIQUE_POINTS = 3;
const MIN_SCORE = 3;

const usable = (v: string | null | undefined): v is string => !!v && !ENTITY_STOPLIST.has(v.trim().toLowerCase());

export interface RelatedOptions {
  limit?: number;
  // Indicators not yet linked to the case (e.g. an investigation still running).
  extraIndicators?: Array<{ type: IndicatorType; value: string }>;
}

export async function findRelatedCases(caseId: string, options: RelatedOptions = {}): Promise<RelatedCase[]> {
  const limit = options.limit ?? 8;
  const kase = await db.case.findUnique({
    where: { id: caseId },
    select: {
      sourceType: true,
      sourceRef: true,
      metadata: true,
      indicators: { select: { indicatorId: true } },
      mitreTechniques: { select: { techniqueId: true } },
    },
  });
  if (!kase) return [];

  const scores = new Map<string, { score: number; reasons: string[]; techniquePoints: number }>();
  const add = (id: string, points: number, reason: string, technique = false) => {
    if (id === caseId) return;
    const entry = scores.get(id) ?? { score: 0, reasons: [], techniquePoints: 0 };
    if (technique) {
      if (entry.techniquePoints >= MAX_TECHNIQUE_POINTS) return;
      entry.techniquePoints += points;
    }
    entry.score += points;
    if (!entry.reasons.includes(reason)) entry.reasons.push(reason);
    scores.set(id, entry);
  };

  // --- shared indicators
  const indicatorIds = new Set(kase.indicators.map((i) => i.indicatorId));
  if (options.extraIndicators?.length) {
    const extra = await db.threatIndicator.findMany({
      where: { OR: options.extraIndicators.map((i) => ({ type: i.type, value: i.value })) },
      select: { id: true },
    });
    extra.forEach((i) => indicatorIds.add(i.id));
  }
  if (indicatorIds.size) {
    const indicators = await db.threatIndicator.findMany({
      where: { id: { in: [...indicatorIds] } },
      select: { id: true, value: true, type: true, maliciousScore: true, _count: { select: { caseLinks: true } } },
    });
    const useful = indicators.filter((i) => i._count.caseLinks <= MAX_INDICATOR_FANOUT);
    const links = await db.caseIndicator.findMany({
      where: { indicatorId: { in: useful.map((i) => i.id) }, caseId: { not: caseId } },
      select: { caseId: true, indicatorId: true },
    });
    const byId = new Map(useful.map((i) => [i.id, i]));
    for (const link of links) {
      const ioc = byId.get(link.indicatorId)!;
      const malicious = (ioc.maliciousScore ?? 0) >= 0.4;
      add(link.caseId, malicious ? WEIGHT.maliciousIndicator : WEIGHT.indicator, `Shared ${ioc.type.toLowerCase().replace("_", " ")} ${ioc.value}`);
    }
  }

  // --- shared hosts / accounts (from linked telemetry and case metadata)
  const meta = (kase.metadata ?? {}) as Record<string, unknown>;
  const [hostRows, userRows] = await Promise.all([
    db.securityEvent.findMany({ where: { caseId, hostName: { not: null } }, distinct: ["hostName"], select: { hostName: true }, take: 50 }),
    db.securityEvent.findMany({ where: { caseId, userName: { not: null } }, distinct: ["userName"], select: { userName: true }, take: 50 }),
  ]);
  const hosts = new Set([...hostRows.map((r) => r.hostName), meta.hostName as string | undefined].filter(usable));
  const users = new Set([...userRows.map((r) => r.userName), meta.userName as string | undefined].filter(usable));

  if (hosts.size || users.size) {
    const or = [
      ...(hosts.size ? [{ hostName: { in: [...hosts] } }] : []),
      ...(users.size ? [{ userName: { in: [...users] } }] : []),
    ];
    const events = await db.securityEvent.findMany({
      where: { caseId: { not: null }, NOT: { caseId }, OR: or },
      distinct: ["caseId", "hostName", "userName"],
      select: { caseId: true, hostName: true, userName: true },
      take: 2000,
    });
    for (const e of events) {
      if (e.hostName && hosts.has(e.hostName)) add(e.caseId!, WEIGHT.entity, `Same host ${e.hostName}`);
      if (e.userName && users.has(e.userName)) add(e.caseId!, WEIGHT.entity, `Same account ${e.userName}`);
    }
    // SIEM cases are keyed by risk object even when their events were trimmed.
    const refs = [...[...users].map((u) => `user:${u}`), ...[...hosts].map((h) => `host:${h}`)];
    const siem = await db.case.findMany({ where: { sourceType: "SIEM_ALERT", sourceRef: { in: refs }, NOT: { id: caseId } }, select: { id: true, sourceRef: true } });
    for (const c of siem) {
      const sep = c.sourceRef!.indexOf(":");
      const kind = c.sourceRef!.slice(0, sep);
      const value = c.sourceRef!.slice(sep + 1);
      add(c.id, WEIGHT.entity, kind === "user" ? `Same account ${value}` : `Same host ${value}`);
    }
  }

  // --- same AI agent
  if (kase.sourceType === "AGENT_GOVERNANCE" && kase.sourceRef) {
    const sameAgent = await db.case.findMany({ where: { sourceType: "AGENT_GOVERNANCE", sourceRef: kase.sourceRef, NOT: { id: caseId } }, select: { id: true } });
    sameAgent.forEach((c) => add(c.id, WEIGHT.agent, "Same AI agent"));
  }

  // --- ATT&CK overlap (only reinforces evidence-based matches)
  const techniqueIds = kase.mitreTechniques.map((t) => t.techniqueId);
  if (techniqueIds.length && scores.size) {
    const overlaps = await db.caseMitreTechnique.findMany({
      where: { techniqueId: { in: techniqueIds }, caseId: { in: [...scores.keys()] } },
      select: { caseId: true, techniqueId: true },
    });
    for (const o of overlaps) add(o.caseId, WEIGHT.technique, `Shared technique ${o.techniqueId}`, true);
  }

  const ranked = [...scores.entries()].filter(([, s]) => s.score >= MIN_SCORE);
  if (ranked.length === 0) return [];
  const cases = await db.case.findMany({
    where: { id: { in: ranked.map(([id]) => id) } },
    select: { id: true, title: true, sourceType: true, severity: true, status: true, verdict: true, rootCauseNarrative: true, createdAt: true },
  });
  const byCase = new Map(cases.map((c) => [c.id, c]));
  return ranked
    .flatMap(([id, s]) => {
      const c = byCase.get(id);
      return c ? [{ ...c, score: s.score, reasons: s.reasons }] : [];
    })
    .sort((a, b) => b.score - a.score || b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, limit);
}
