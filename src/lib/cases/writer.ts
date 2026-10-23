import { after } from "next/server";
import type {
  CaseSeverity,
  CaseSource,
  CaseStatus,
  DetectionSource,
  IndicatorType,
  Prisma,
} from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { maxSeverity, severityRank } from "@/lib/severity";
import { getTactic, getTechnique, parentTechniqueId, resolveTechnique } from "@/lib/mitre/catalog";
import { recordIndicator, enrichCaseIndicators } from "@/lib/threat-intel/service";
import { evaluatePlaybooksForCase } from "@/lib/playbooks/engine";

// The single write path every module uses to file a Case — so detections,
// timeline, MITRE mappings, indicators, playbook triggers, and the audit
// trail behave identically whether the case came from Agent Governance,
// Investigations, Forensics, or the SIEM detection engine.

export interface NewDetection {
  source: DetectionSource;
  ruleId: string;
  title: string;
  severity: CaseSeverity;
  evidence: unknown;
  fingerprint?: string;
}

export interface NewTimelineEntry {
  occurredAt: Date;
  actor?: string | null;
  action: string;
  detail?: string | null;
  evidence?: unknown;
}

export interface NewIndicator {
  type: IndicatorType;
  value: string;
  role?: string;
}

export interface CaseArtifacts {
  detections?: NewDetection[];
  timeline?: NewTimelineEntry[];
  // Technique IDs or free text containing one ("T1003 - OS Credential Dumping")
  techniques?: Array<string | { id: string; confidence?: number }>;
  indicators?: NewIndicator[];
  eventIds?: string[];
}

export interface NewCase extends CaseArtifacts {
  sourceType: CaseSource;
  title: string;
  summary?: string | null;
  severity: CaseSeverity;
  status?: CaseStatus;
  confidence?: number | null;
  verdict?: string | null;
  riskScore?: number | null;
  sourceRef?: string | null;
  rootCauseNarrative?: string | null;
  metadata?: Record<string, unknown>;
  resolvedAt?: Date | null;
  actorId?: string;
  // Skip playbook evaluation / enrichment (e.g. while a pipeline is still
  // filling the case in; call finalizeCase when it's done).
  deferPipelines?: boolean;
}

function json(value: unknown) {
  return JSON.parse(JSON.stringify(value ?? null)) as Prisma.InputJsonValue;
}

export async function ensureTechniques(refs: CaseArtifacts["techniques"] = []) {
  const resolved = new Map<string, number | undefined>();
  for (const ref of refs) {
    const text = typeof ref === "string" ? ref : ref.id;
    const technique = resolveTechnique(text);
    if (technique) {
      const confidence = typeof ref === "string" ? undefined : ref.confidence;
      const prev = resolved.get(technique.id);
      resolved.set(technique.id, confidence === undefined ? prev : Math.max(confidence, prev ?? 0));
    }
  }
  if (resolved.size === 0) return resolved;

  const ids = new Set<string>();
  for (const id of resolved.keys()) {
    ids.add(id);
    const parent = parentTechniqueId(id);
    if (parent && getTechnique(parent)) ids.add(parent);
  }
  const techniques = [...ids].map((id) => getTechnique(id)!);
  const tacticIds = [...new Set(techniques.map((t) => t.tactic))];

  await db.mitreTactic.createMany({
    data: tacticIds.map((id) => ({ id, name: getTactic(id)!.name })),
    skipDuplicates: true,
  });
  await db.mitreTechnique.createMany({
    data: techniques.map((t) => ({
      id: t.id,
      name: t.name,
      tacticId: t.tactic,
      isSubtechnique: t.id.includes("."),
      parentId: parentTechniqueId(t.id),
    })),
    skipDuplicates: true,
  });
  return resolved;
}

async function attachArtifacts(caseId: string, artifacts: CaseArtifacts) {
  let detections = 0;
  if (artifacts.detections?.length) {
    const result = await db.detection.createMany({
      data: artifacts.detections.map((d) => ({
        caseId,
        source: d.source,
        ruleId: d.ruleId,
        title: d.title,
        severity: d.severity,
        evidence: json(d.evidence),
        fingerprint: d.fingerprint,
      })),
      skipDuplicates: true,
    });
    detections = result.count;
  }

  if (artifacts.timeline?.length) {
    await db.timelineEntry.createMany({
      data: artifacts.timeline.map((t) => ({
        caseId,
        occurredAt: t.occurredAt,
        actor: t.actor ?? null,
        action: t.action,
        detail: t.detail ?? null,
        evidence: t.evidence === undefined ? undefined : json(t.evidence),
      })),
    });
  }

  const techniques = await ensureTechniques(artifacts.techniques);
  if (techniques.size) {
    await db.caseMitreTechnique.createMany({
      data: [...techniques].map(([techniqueId, confidence]) => ({ caseId, techniqueId, confidence: confidence ?? null })),
      skipDuplicates: true,
    });
  }

  if (artifacts.indicators?.length) {
    const seen = new Set<string>();
    for (const ioc of artifacts.indicators) {
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const indicator = await recordIndicator(ioc.type, ioc.value);
      await db.caseIndicator.upsert({
        where: { caseId_indicatorId: { caseId, indicatorId: indicator.id } },
        update: {},
        create: { caseId, indicatorId: indicator.id, role: ioc.role },
      });
    }
  }

  if (artifacts.eventIds?.length) {
    await db.securityEvent.updateMany({ where: { id: { in: artifacts.eventIds } }, data: { caseId } });
  }

  return { detections };
}

// Provider enrichment hits external APIs, so it runs after the response is
// sent when called from a request; outside one (seed scripts, tests) it just
// runs detached.
function scheduleEnrichment(caseId: string) {
  const job = () => enrichCaseIndicators(caseId).catch((err) => console.error("enrichment failed", caseId, err));
  try {
    after(job);
  } catch {
    void job();
  }
}

export async function finalizeCase(caseId: string) {
  await evaluatePlaybooksForCase(caseId);
  scheduleEnrichment(caseId);
}

export async function createCase(input: NewCase) {
  const { detections, timeline, techniques, indicators, eventIds, actorId, deferPipelines, metadata, ...fields } = input;

  const kase = await db.case.create({
    data: { ...fields, metadata: metadata === undefined ? undefined : json(metadata) },
  });
  await attachArtifacts(kase.id, { detections, timeline, techniques, indicators, eventIds });

  await logAction({
    actorId,
    caseId: kase.id,
    action: "case.created",
    detail: { sourceType: kase.sourceType, severity: kase.severity, title: kase.title },
  });

  if (!deferPipelines) await finalizeCase(kase.id);
  return kase;
}

export interface CaseUpdate extends CaseArtifacts {
  severity?: CaseSeverity;
  riskScore?: number;
  actorId?: string;
}

// Correlation path: new evidence for an existing case. Severity and risk only
// ever ratchet up; re-evaluates playbooks so an escalation can trigger them.
export async function appendToCase(caseId: string, update: CaseUpdate) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId } });
  const { severity, riskScore, actorId, ...artifacts } = update;

  const nextSeverity = severity ? maxSeverity(kase.severity, severity) : kase.severity;
  const nextRisk = riskScore !== undefined ? Math.max(kase.riskScore ?? 0, riskScore) : kase.riskScore;
  if (nextSeverity !== kase.severity || nextRisk !== kase.riskScore) {
    await db.case.update({ where: { id: caseId }, data: { severity: nextSeverity, riskScore: nextRisk } });
  }

  const { detections } = await attachArtifacts(caseId, artifacts);

  await logAction({
    actorId,
    caseId,
    action: "case.correlated",
    detail: {
      newDetections: detections,
      escalated: severityRank(nextSeverity) > severityRank(kase.severity) ? nextSeverity : undefined,
    },
  });

  await finalizeCase(caseId);
  return { detections };
}
