import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { runPlaybooksForCase } from "@/lib/playbooks/engine";
import { DETECTORS } from "./detectors";
import type { DetectionResult, NormalizedEvent } from "./types";
import type { CaseSeverity, DetectionSource } from "@prisma/client";

// Ported from signal-fusion's detection/engine.ts DetectionEngine. Each
// firing detection becomes a Case + Detection on the unified model instead
// of signal-fusion's standalone Alert row. Playbook auto-execution/approval
// (originally inline evaluateTriggers/executePlaybook/createApprovalRequest
// calls) now goes through runPlaybooksForCase, generalized to trigger from
// any Case, not just SIEM alerts.

const DETECTOR_NAME_TO_SOURCE: Record<string, DetectionSource> = {
  GeoVelocityDetector: "GEO_VELOCITY",
  FSMChainDetector: "FSM_CHAIN",
  AnomalousActionDetector: "ANOMALOUS_ACTION",
  ThreatIntelDetector: "THREAT_INTEL_MATCH",
  ReconnaissanceDetector: "RECONNAISSANCE",
  CredentialHarvestingDetector: "CREDENTIAL_HARVESTING",
  LateralMovementDetector: "LATERAL_MOVEMENT",
  DataExfiltrationDetector: "DATA_EXFILTRATION",
  PersistenceDetector: "PERSISTENCE",
  DefenseEvasionDetector: "DEFENSE_EVASION",
  ImpactDetector: "IMPACT",
};

const CRITICAL_SIGNAL_MARKERS = ["ransomware", "credential_dumping", "mimikatz", "data_destruction"];
const HIGH_SIGNAL_MARKERS = [
  "lateral_movement",
  "exfiltration",
  "persistence",
  "privilege_escalation",
  "malware",
];
const MEDIUM_SIGNAL_MARKERS = ["reconnaissance", "discovery", "suspicious", "anomalous"];

function severityMultiplier(signals: string[]): number {
  const lower = signals.map((s) => s.toLowerCase());
  if (CRITICAL_SIGNAL_MARKERS.some((m) => lower.some((s) => s.includes(m)))) return 10;
  if (HIGH_SIGNAL_MARKERS.some((m) => lower.some((s) => s.includes(m)))) return 7;
  if (MEDIUM_SIGNAL_MARKERS.some((m) => lower.some((s) => s.includes(m)))) return 4;
  return 2;
}

function severityFromRiskScore(riskScore: number): CaseSeverity {
  if (riskScore >= 700) return "CRITICAL";
  if (riskScore >= 400) return "HIGH";
  if (riskScore >= 100) return "MEDIUM";
  return "LOW";
}

export interface EngineRunResult {
  caseIds: string[];
  detectionCount: number;
}

export async function runDetections(events: NormalizedEvent[]): Promise<EngineRunResult> {
  const allDetections: DetectionResult[] = [];
  for (const detector of DETECTORS) {
    allDetections.push(...detector.run(events));
  }

  const caseIds: string[] = [];

  for (const detection of allDetections) {
    const riskScore = Math.min(detection.confidence * 100 * severityMultiplier(detection.signals), 1000);
    const severity = severityFromRiskScore(riskScore);
    const primaryEvent = detection.matchedEvents[0];
    const riskObject = primaryEvent?.network.sourceIp ?? primaryEvent?.actor.user ?? "unknown";

    const kase = await db.case.create({
      data: {
        sourceType: "SIEM_ALERT",
        title: `${detection.detector}: ${detection.reasoning[0] ?? detection.signals[0]}`,
        summary: detection.reasoning.join(" "),
        severity,
        status: "OPEN",
        confidence: detection.confidence,
        riskScore,
        sourceRef: primaryEvent?.id,
        metadata: {
          signals: detection.signals,
          mitreTactics: detection.mitreTactics,
          mitreTechniques: detection.mitreTechniques,
          riskObject,
        } as never,
      },
    });

    await db.detection.create({
      data: {
        caseId: kase.id,
        source: DETECTOR_NAME_TO_SOURCE[detection.detector] ?? "ANOMALOUS_ACTION",
        ruleId: `${detection.detector}@@${Date.now()}`,
        title: detection.signals.join(", "),
        severity,
        evidence: {
          matchedEventIds: detection.matchedEvents.map((e) => e.id),
          reasoning: detection.reasoning,
          mitreTactics: detection.mitreTactics,
          mitreTechniques: detection.mitreTechniques,
        } as never,
      },
    });

    for (const event of detection.matchedEvents) {
      await db.timelineEntry.create({
        data: {
          caseId: kase.id,
          occurredAt: event.timestamp,
          actor: event.actor.user ?? event.actor.process ?? event.actor.service,
          action: event.eventType,
          detail: `via ${event.source}`,
          evidence: event as never,
        },
      });
      await db.ingestedEvent.update({ where: { id: event.id }, data: { caseId: kase.id } });
    }

    await logAction({
      caseId: kase.id,
      action: "detection.case_created",
      detail: { detector: detection.detector, riskScore, severity },
    });

    try {
      await runPlaybooksForCase(kase);
    } catch (err) {
      // Don't fail case creation if playbook execution fails.
      console.error(`Error running playbooks for case ${kase.id}:`, err);
    }

    caseIds.push(kase.id);
  }

  return { caseIds, detectionCount: allDetections.length };
}
