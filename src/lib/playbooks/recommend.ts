import type { PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { getTechnique, getTactic, parentTechniqueId } from "@/lib/mitre/catalog";
import { ACTION_LABEL } from "@/lib/response/executor";
import { matchesTrigger, parseTrigger, type CaseSnapshot } from "@/lib/playbooks/trigger";
import { loadCaseSnapshot } from "@/lib/playbooks/engine";
import { CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { severityRank } from "@/lib/severity";

// Playbook recommendations: asip retrieved runbook passages by embedding
// similarity ("playbook RAG"). Here every enabled playbook is scored against
// the case on things an analyst can check — shared ATT&CK techniques, the
// case source and detections, distinctive words, and whether the evidence
// holds a target for each step — and every recommendation says why.

export interface CaseTargets {
  hosts: string[];
  ips: string[];
  users: string[];
  processes: string[];
  hashes: string[];
  emails: string[];
  domains: string[];
  agents: string[];
}

export interface PlaybookCandidate {
  id: string;
  name: string;
  description: string | null;
  triggerCondition: unknown;
  actions: Array<{ actionType: PlaybookActionType }>;
}

export interface PlaybookRecommendation {
  id: string;
  name: string;
  description: string | null;
  score: number;
  exactMatch: boolean;
  reasons: string[];
  // Containment steps with nothing in the evidence to act on.
  noTarget: string[];
}

const TARGET_FOR: Partial<Record<PlaybookActionType, keyof CaseTargets | Array<keyof CaseTargets>>> = {
  ISOLATE_HOST: "hosts",
  RELEASE_HOST: "hosts",
  COLLECT_LOGS: "hosts",
  COLLECT_FORENSICS: "hosts",
  BLOCK_IP: "ips",
  UNBLOCK_IP: "ips",
  DISABLE_USER: "users",
  ENABLE_USER: "users",
  KILL_PROCESS: "processes",
  QUARANTINE_FILE: "hashes",
  BLOCK_SENDER: ["emails", "domains"],
  REVOKE_AGENT: "agents",
};

const STOPWORDS = new Set("about above after again against alert alerts also because before being below between both case cases could does doing down during each from further have having here into itself just more most other over same should some such than that their them then there these they this those through under until very what when where which while with would your playbook playbooks response respond host hosts user users file files".split(" "));

function words(text: string): Set<string> {
  return new Set((text.toLowerCase().match(/[a-z][a-z0-9-]{3,}/g) ?? []).filter((w) => !STOPWORDS.has(w)));
}

const MIN_SCORE = 4;

// Pure: rank the candidates for one case.
export function rankPlaybooks(snapshot: CaseSnapshot, caseText: string, targets: CaseTargets, playbooks: PlaybookCandidate[], limit = 5): PlaybookRecommendation[] {
  const caseWords = words(caseText);
  const caseTactics = new Set(snapshot.techniqueIds.map((id) => getTechnique(id)?.tactic ?? getTechnique(parentTechniqueId(id) ?? "")?.tactic).filter(Boolean));
  const out: PlaybookRecommendation[] = [];

  for (const pb of playbooks) {
    const trigger = parseTrigger(pb.triggerCondition);
    const reasons: string[] = [];
    let score = 0;
    const exactMatch = !!trigger && matchesTrigger(trigger, snapshot);
    if (exactMatch) {
      score += 10;
      reasons.push("Its trigger matches this case");
    }

    if (trigger?.techniques?.length) {
      const hits = trigger.techniques.filter((wanted) => snapshot.techniqueIds.some((id) => id === wanted || id.startsWith(`${wanted}.`) || wanted.startsWith(`${id}.`)));
      if (hits.length) {
        score += Math.min(12, hits.length * 5);
        reasons.push(`Covers ${hits.map((t) => `${t} ${getTechnique(t)?.name ?? ""}`.trim()).join(", ")}`);
      } else {
        const tactics = [...new Set(trigger.techniques.map((t) => getTechnique(t)?.tactic).filter((t): t is string => !!t && caseTactics.has(t)))];
        if (tactics.length) {
          score += Math.min(3, tactics.length);
          reasons.push(`Same tactic: ${tactics.map((t) => getTactic(t)?.name ?? t).join(", ")}`);
        }
      }
    }
    if (trigger?.sourceTypes?.includes(snapshot.sourceType)) {
      score += 2;
      reasons.push(`Written for ${CASE_SOURCE_LABEL[snapshot.sourceType].toLowerCase()} cases`);
    }
    const detections = trigger?.detectionSources?.filter((d) => snapshot.detectionSources.includes(d as never)) ?? [];
    if (detections.length) {
      score += 2;
      reasons.push(`Responds to ${detections.map((d) => d.toLowerCase().replaceAll("_", " ")).join(", ")} detections`);
    }
    const shared = [...words(`${pb.name} ${pb.description ?? ""}`)].filter((w) => caseWords.has(w));
    if (shared.length) {
      score += Math.min(4, shared.length);
      reasons.push(`Mentions ${shared.slice(0, 4).join(", ")}`);
    }
    if (trigger?.minSeverity && severityRank(snapshot.severity) < severityRank(trigger.minSeverity)) {
      score -= 2;
      reasons.push(`Meant for ${trigger.minSeverity.toLowerCase()} severity and above`);
    }

    const noTarget = pb.actions
      .map((a) => a.actionType)
      .filter((type) => {
        const need = TARGET_FOR[type];
        if (!need) return false;
        return (Array.isArray(need) ? need : [need]).every((k) => targets[k].length === 0);
      })
      .map((type) => ACTION_LABEL[type]);
    const containment = pb.actions.filter((a) => TARGET_FOR[a.actionType]).length;
    if (containment > 0 && noTarget.length === containment) score -= 2;

    if (score >= MIN_SCORE) out.push({ id: pb.id, name: pb.name, description: pb.description, score, exactMatch, reasons, noTarget: [...new Set(noTarget)] });
  }
  return out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)).slice(0, limit);
}

export async function enabledPlaybooks(): Promise<PlaybookCandidate[]> {
  return db.playbook.findMany({
    where: { enabled: true },
    select: { id: true, name: true, description: true, triggerCondition: true, actions: { select: { actionType: true } } },
    orderBy: { priority: "desc" },
  });
}

export async function recommendPlaybooks(caseId: string, targets: CaseTargets, limit = 5): Promise<PlaybookRecommendation[]> {
  const [snapshot, detections, playbooks] = await Promise.all([
    loadCaseSnapshot(caseId),
    db.detection.findMany({ where: { caseId }, select: { title: true }, take: 50 }),
    enabledPlaybooks(),
  ]);
  if (!snapshot) return [];
  const text = [snapshot.case.title, snapshot.case.summary ?? "", ...detections.map((d) => d.title)].join(" ");
  return rankPlaybooks(snapshot, text, targets, playbooks, limit);
}
