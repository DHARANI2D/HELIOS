import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { toNormalizedEvent } from "@/lib/detection/types";
import { buildEntityGraph } from "./entity-graph";
import { runInvestigationSwarm } from "./orchestrator";
import type { CaseSeverity } from "@prisma/client";

const SEVERITY_MAP: Record<string, CaseSeverity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

function parseTimelineTimestamp(entry: string, baseDate: Date): Date {
  const match = entry.match(/^(\d{2}):(\d{2}):(\d{2})/);
  if (!match) return baseDate;
  const d = new Date(baseDate);
  d.setHours(Number(match[1]), Number(match[2]), Number(match[3]), 0);
  return d;
}

async function getLinkedEvents(linkedCaseId: string) {
  // IngestedEvent.caseId is 1:1 (last detector to touch the row wins), so
  // it can't answer "which events fed this specific case" once a single
  // event matches more than one detector — Detection.evidence carries the
  // exact matched-event IDs per case, so read from there instead.
  const detections = await db.detection.findMany({ where: { caseId: linkedCaseId } });
  const eventIds = new Set<string>();
  for (const d of detections) {
    const evidence = d.evidence as { matchedEventIds?: string[] } | null;
    evidence?.matchedEventIds?.forEach((id) => eventIds.add(id));
  }
  if (eventIds.size === 0) return [];
  return db.ingestedEvent.findMany({
    where: { id: { in: [...eventIds] } },
    orderBy: { timestamp: "asc" },
  });
}

export async function createInvestigation(
  alertTitle: string,
  alertDetails: string,
  linkedCaseId?: string,
) {
  const linkedEvents = linkedCaseId ? await getLinkedEvents(linkedCaseId) : [];

  const normalizedEvents = linkedEvents.map(toNormalizedEvent);
  const graphData = buildEntityGraph(normalizedEvents);
  const sampleLogs = normalizedEvents.map((e) => ({
    timestamp: e.timestamp.toISOString(),
    source: e.source,
    eventType: e.eventType,
    actor: e.actor,
    network: e.network,
  }));

  const kase = await db.case.create({
    data: {
      sourceType: "SOC_INVESTIGATION",
      title: alertTitle,
      summary: alertDetails,
      severity: "MEDIUM",
      status: "INVESTIGATING",
      sourceRef: linkedCaseId,
      metadata: { linkedCaseId, eventCount: normalizedEvents.length } as never,
    },
  });

  const swarm = await runInvestigationSwarm(alertTitle, alertDetails, graphData, sampleLogs);

  await db.case.update({
    where: { id: kase.id },
    data: {
      severity: SEVERITY_MAP[swarm.triage.severity.toLowerCase()] ?? "MEDIUM",
      confidence: swarm.rca.confidence_score,
      verdict: swarm.qa.is_valid ? "confirmed" : "unconfirmed",
      rootCauseNarrative: swarm.rca.root_cause,
      status: swarm.qa.is_valid ? "RESOLVED" : "INVESTIGATING",
      resolvedAt: swarm.qa.is_valid ? new Date() : null,
      metadata: {
        linkedCaseId,
        eventCount: normalizedEvents.length,
        triage: swarm.triage,
        qa: swarm.qa,
        qaIterations: swarm.qaIterations,
        graphData,
        finalReport: swarm.finalReport,
      } as never,
    },
  });

  await db.detection.create({
    data: {
      caseId: kase.id,
      source: "ANOMALOUS_ACTION",
      ruleId: `swarm-triage@@${Date.now()}`,
      title: `${swarm.triage.alert_type} — ${swarm.triage.mitre_tactic}`,
      severity: SEVERITY_MAP[swarm.triage.severity.toLowerCase()] ?? "MEDIUM",
      evidence: { triage: swarm.triage, qa: swarm.qa } as never,
    },
  });

  const baseDate = kase.createdAt;
  for (const entry of swarm.rca.timeline) {
    await db.timelineEntry.create({
      data: {
        caseId: kase.id,
        occurredAt: parseTimelineTimestamp(entry, baseDate),
        action: "rca_finding",
        detail: entry,
      },
    });
  }

  await logAction({
    caseId: kase.id,
    action: "investigation.swarm_completed",
    detail: {
      qaValid: swarm.qa.is_valid,
      qaIterations: swarm.qaIterations,
      confidence: swarm.rca.confidence_score,
    },
  });

  return kase.id;
}

export async function getInvestigation(caseId: string) {
  return db.case.findUnique({
    where: { id: caseId },
    include: {
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: { occurredAt: "asc" } },
    },
  });
}

export async function listInvestigations() {
  return db.case.findMany({
    where: { sourceType: "SOC_INVESTIGATION" },
    orderBy: { createdAt: "desc" },
    take: 100,
  });
}
