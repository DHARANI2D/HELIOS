import { db } from "@/lib/db";

// Every module records its MITRE technique references in a slightly
// different shape (Detection.evidence.mitreTechniques as a flat array for
// signal-fusion-style detectors, Case.metadata.attachments[].mitreTechniques
// per-attachment for the forensics module, a single free-text
// triage.mitre_tactic string for Investigations). Rather than force every
// module to conform to one storage shape retroactively, this walks each
// case's metadata and detection evidence looking for MITRE technique ID
// patterns (T####  or T####.###) wherever they appear, and ties the count
// back to the seeded MitreTechnique/MitreTactic reference set.

const TECHNIQUE_ID_PATTERN = /T\d{4}(?:\.\d{3})?/g;

function extractTechniqueIds(value: unknown, found: Set<string>): void {
  if (typeof value === "string") {
    const matches = value.match(TECHNIQUE_ID_PATTERN);
    matches?.forEach((m) => found.add(m));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v) => extractTechniqueIds(v, found));
    return;
  }
  if (value && typeof value === "object") {
    Object.values(value).forEach((v) => extractTechniqueIds(v, found));
  }
}

export interface TechniqueCoverage {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  caseCount: number;
}

export interface TacticCoverage {
  id: string;
  name: string;
  techniqueCount: number;
  caseCount: number;
  techniques: TechniqueCoverage[];
}

export async function getMitreCoverage(): Promise<TacticCoverage[]> {
  const [tactics, techniques, cases] = await Promise.all([
    db.mitreTactic.findMany(),
    db.mitreTechnique.findMany(),
    db.case.findMany({
      select: { id: true, metadata: true, detections: { select: { evidence: true } } },
    }),
  ]);

  const techniqueById = new Map(techniques.map((t) => [t.id, t]));
  const caseCountByTechnique = new Map<string, number>();

  for (const kase of cases) {
    const found = new Set<string>();
    extractTechniqueIds(kase.metadata, found);
    for (const d of kase.detections) extractTechniqueIds(d.evidence, found);

    for (const techniqueId of found) {
      caseCountByTechnique.set(techniqueId, (caseCountByTechnique.get(techniqueId) ?? 0) + 1);
    }
  }

  const tacticMap = new Map<string, TacticCoverage>(
    tactics.map((t) => [t.id, { id: t.id, name: t.name, techniqueCount: 0, caseCount: 0, techniques: [] }]),
  );

  for (const [techniqueId, count] of caseCountByTechnique) {
    const technique = techniqueById.get(techniqueId);
    if (!technique) continue; // technique ID mentioned in free text but not in our seeded reference set

    const tactic = tacticMap.get(technique.tacticId);
    if (!tactic) continue;

    tactic.techniques.push({
      id: technique.id,
      name: technique.name,
      tacticId: technique.tacticId,
      tacticName: tactic.name,
      caseCount: count,
    });
    tactic.techniqueCount += 1;
    tactic.caseCount += count;
  }

  return [...tacticMap.values()].sort((a, b) => b.caseCount - a.caseCount);
}
