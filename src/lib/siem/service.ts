import { randomUUID } from "node:crypto";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { maxSeverity } from "@/lib/severity";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import {
  appendToCase,
  createCase,
  type CaseArtifacts,
  type NewIndicator,
} from "@/lib/cases/writer";
import { extractIndicators, isPrivateIp } from "@/lib/threat-intel/indicators";
import { fromEventRow, normalize, toEventRow } from "@/lib/siem/adapters";
import { fingerprintFor, runDetections, severityForRisk } from "@/lib/siem/engine";
import type { ScoredDetection, TelemetrySource, UnifiedEvent } from "@/lib/siem/types";
import type { SecurityDomain } from "@prisma/client";
import { touchEndpoints } from "@/lib/endpoints/service";
import { loadIntelSnapshot } from "@/lib/threat-intel/snapshot";

// Ingestion → detection → correlation. Replaces signal-fusion's
// IngestionService + DetectionEngine.runDetections, which re-ran every
// detector over the entire event table on each ingest and filed one alert
// per detection (so the same finding was re-filed every run). Here detection
// runs over a 24h window, fingerprints suppress repeats, and detections about
// the same user/host/IP correlate into one open case.

const WINDOW_MS = 24 * 60 * 60 * 1000;
const WINDOW_EVENT_CAP = 5000;

export interface IngestItem {
  source: TelemetrySource;
  data: Record<string, unknown>;
}

export interface IngestSummary {
  batchId: string;
  eventsIngested: number;
  detectionsFound: number;
  newDetections: number;
  casesCreated: number;
  casesUpdated: number;
  caseIds: string[];
}

function humanize(ruleId: string) {
  const s = ruleId.replaceAll("_", " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function describeEvent(e: UnifiedEvent): string {
  const who = e.actor.user ? ` by ${e.actor.user}` : "";
  const where = e.actor.host ? ` on ${e.actor.host}` : "";
  switch (e.source) {
    case "auth":
      return `${e.eventType} for ${e.actor.user ?? "unknown"}${e.network.sourceIp ? ` from ${e.network.sourceIp}` : ""}${e.network.geo ? ` (${e.network.geo})` : ""}`;
    case "endpoint":
      return `${e.eventType}${who}${where}: ${e.actor.process ?? "unknown process"}`;
    case "network": {
      const port = e.network.destPort ? `:${e.network.destPort}` : "";
      const proto = e.metadata.type ? ` (${e.metadata.type})` : "";
      return `${e.network.sourceIp ?? "?"} → ${e.network.destIp ?? "?"}${port}${proto}${e.metadata.url ? ` ${e.metadata.url}` : ""}`;
    }
    case "cloud":
      return `${e.eventType}${who} on ${e.actor.service ?? "unknown resource"}`;
  }
}

function indicatorsFor(events: UnifiedEvent[]): NewIndicator[] {
  const out: NewIndicator[] = [];
  for (const e of events) {
    if (e.network.sourceIp && !isPrivateIp(e.network.sourceIp)) out.push({ type: "IP", value: e.network.sourceIp, role: "source_ip" });
    if (e.network.destIp && !isPrivateIp(e.network.destIp)) out.push({ type: "IP", value: e.network.destIp, role: "destination_ip" });
    const text = [e.actor.process, e.metadata.url, e.metadata.domain, e.metadata.hash, e.metadata.query]
      .filter((v) => typeof v === "string")
      .join(" ");
    for (const ioc of extractIndicators(text)) out.push({ ...ioc, role: `observed_${ioc.type.toLowerCase()}` });
  }
  return out;
}

export function buildCaseArtifacts(group: ScoredDetection[]): CaseArtifacts {
  const events = new Map<string, UnifiedEvent>();
  for (const d of group) for (const e of d.matchedEvents) events.set(e.id, e);
  const ordered = [...events.values()].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  return {
    detections: group.map((d) => ({
      source: d.detectionSource,
      ruleId: `${d.detector}:${d.ruleId}`,
      title: `${humanize(d.ruleId)} — ${d.reasoning[0]}`.slice(0, 240),
      severity: severityForRisk(d.riskScore),
      fingerprint: fingerprintFor(d),
      evidence: {
        detector: d.detector,
        signals: d.signals,
        confidence: d.confidence,
        riskScore: d.riskScore,
        reasoning: d.reasoning,
        mitreTactics: d.mitreTactics,
        mitreTechniques: d.mitreTechniques,
        matchedEventIds: d.matchedEvents.map((e) => e.id),
      },
    })),
    timeline: [
      ...ordered.map((e) => ({
        occurredAt: e.timestamp,
        actor: e.actor.user ?? e.actor.host ?? e.network.sourceIp ?? null,
        action: `${e.source}.${e.eventType.toLowerCase()}`,
        detail: describeEvent(e),
        evidence: { eventId: e.id },
      })),
      ...group.map((d) => ({
        occurredAt: new Date(Math.max(...d.matchedEvents.map((e) => e.timestamp.getTime()))),
        actor: "detection-engine",
        action: "detection.fired",
        detail: `${d.detector} · ${humanize(d.ruleId)} (risk ${d.riskScore}, confidence ${Math.round(d.confidence * 100)}%)`,
      })),
    ],
    techniques: group.flatMap((d) => d.mitreTechniques.map((t) => ({ id: t, confidence: d.confidence }))),
    indicators: indicatorsFor(ordered),
    eventIds: ordered.map((e) => e.id),
  };
}

function titleFor(group: ScoredDetection[], riskObject: string, riskObjectType: string) {
  if (group.length === 1) return `${humanize(group[0].ruleId)}: ${riskObjectType} ${riskObject}`;
  const rules = [...new Set(group.map((d) => humanize(d.ruleId)))];
  const shown = rules.slice(0, 3).join(", ");
  return `Correlated activity for ${riskObjectType} ${riskObject}: ${shown}${rules.length > 3 ? ` +${rules.length - 3} more` : ""}`;
}

const DOMAIN_FOR_SOURCE: Record<TelemetrySource, SecurityDomain> = {
  auth: "IDENTITY",
  endpoint: "ENDPOINT",
  network: "NETWORK",
  cloud: "CLOUD",
};

function dominantDomain(group: ScoredDetection[]): SecurityDomain {
  const counts = new Map<TelemetrySource, number>();
  for (const d of group) for (const e of d.matchedEvents) counts.set(e.source, (counts.get(e.source) ?? 0) + 1);
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "endpoint";
  return DOMAIN_FOR_SOURCE[top];
}

// The correlation window is per tenant: one client's telemetry never
// correlates into another client's case.
async function loadWindow(batchId: string, tenantId: string | null): Promise<UnifiedEvent[]> {
  const since = new Date(Date.now() - WINDOW_MS);
  const [batch, recent] = await Promise.all([
    db.securityEvent.findMany({ where: { batchId } }),
    db.securityEvent.findMany({
      where: { platform: "signal-fusion", tenantId, ingestedAt: { gte: since }, NOT: { batchId } },
      orderBy: { ingestedAt: "desc" },
      take: WINDOW_EVENT_CAP,
    }),
  ]);
  return [...recent, ...batch].map(fromEventRow).sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
}

export interface IngestOptions {
  actorId?: string;
  label?: string;
  tenantId?: string | null;
  integrationId?: string;
}

export async function ingestTelemetry(items: IngestItem[], options: IngestOptions = {}): Promise<IngestSummary> {
  const batchId = randomUUID();
  const tenantId = options.tenantId ?? null;
  const rows = items.map((item) => ({ ...toEventRow(normalize(item.source, item.data), batchId), tenantId, integrationId: options.integrationId }));
  if (rows.length) await db.securityEvent.createMany({ data: rows });
  await touchEndpoints(tenantId, rows, { integrationId: options.integrationId });

  const events = await loadWindow(batchId, tenantId);
  const intel = await loadIntelSnapshot(events.flatMap((e) => [e.network.sourceIp, e.network.destIp]).map((value) => ({ type: "IP" as const, value })));
  const detections = runDetections(events, { intel });

  // Drop findings already filed (in an earlier run) or repeated in this one.
  const fingerprints = detections.map(fingerprintFor);
  const existing = new Set(
    (await db.detection.findMany({ where: { fingerprint: { in: fingerprints } }, select: { fingerprint: true } })).map((d) => d.fingerprint),
  );
  const fresh: ScoredDetection[] = [];
  const seen = new Set<string>();
  detections.forEach((d, i) => {
    const fp = fingerprints[i];
    if (existing.has(fp) || seen.has(fp)) return;
    seen.add(fp);
    fresh.push(d);
  });

  const groups = new Map<string, ScoredDetection[]>();
  for (const d of fresh) {
    const key = `${d.riskObjectType}:${d.riskObject}`;
    groups.set(key, [...(groups.get(key) ?? []), d]);
  }

  const caseIds: string[] = [];
  let casesCreated = 0;
  let casesUpdated = 0;
  const since = new Date(Date.now() - WINDOW_MS);

  for (const [key, group] of groups) {
    const severity = maxSeverity(...group.map((d) => severityForRisk(d.riskScore)));
    const riskScore = Math.max(...group.map((d) => d.riskScore));
    const artifacts = buildCaseArtifacts(group);
    const open = await db.case.findFirst({
      where: { sourceType: "SIEM_ALERT", sourceRef: key, tenantId, status: { notIn: CLOSED_STATUSES }, createdAt: { gte: since } },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });

    if (open) {
      await appendToCase(open.id, { ...artifacts, severity, riskScore, actorId: options.actorId });
      caseIds.push(open.id);
      casesUpdated++;
    } else {
      const { riskObject, riskObjectType } = group[0];
      const firstEvent = group[0].matchedEvents[0];
      const kase = await createCase({
        sourceType: "SIEM_ALERT",
        title: titleFor(group, riskObject, riskObjectType),
        summary: group.map((d) => d.reasoning.join(" · ")).join("\n"),
        severity,
        riskScore,
        confidence: Math.max(...group.map((d) => d.confidence)),
        sourceRef: key,
        metadata: {
          riskObject,
          riskObjectType,
          userName: firstEvent?.actor.user,
          hostName: group.flatMap((d) => d.matchedEvents).find((e) => e.actor.host)?.actor.host,
          detectors: [...new Set(group.map((d) => d.detector))],
          batchId,
        },
        actorId: options.actorId,
        tenantId,
        domain: dominantDomain(group),
        ...artifacts,
      });
      caseIds.push(kase.id);
      casesCreated++;
    }
  }

  const summary: IngestSummary = {
    batchId,
    eventsIngested: rows.length,
    detectionsFound: detections.length,
    newDetections: fresh.length,
    casesCreated,
    casesUpdated,
    caseIds,
  };
  await logAction({
    actorId: options.actorId,
    action: "siem.ingest",
    detail: { ...summary, caseIds: undefined, label: options.label, tenantId, integrationId: options.integrationId },
  });
  return summary;
}
