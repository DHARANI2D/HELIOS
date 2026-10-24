import { DETECTORS } from "@/lib/siem/engine";
import { GOVERNANCE_RULE_TECHNIQUES } from "@/lib/governance/runtime";
import { resolveTechnique } from "@/lib/mitre/catalog";
import { INVESTIGATION_RULE_TECHNIQUES } from "@/lib/investigations/heuristics";
import { FORENSICS_RULE_TECHNIQUES } from "@/lib/forensics/files";

// The "detectable" layer of the coverage matrix: which techniques some
// HELIOS rule can actually emit, and which module/rule that is. The
// "observed" layer comes from case_mitre_techniques at query time.

export interface DetectionCapability {
  techniqueId: string;
  module: string;
  rule: string;
}

export function detectionCapabilities(): DetectionCapability[] {
  const caps: DetectionCapability[] = [];
  for (const detector of DETECTORS) {
    for (const t of detector.techniques) caps.push({ techniqueId: t, module: "Cases & Alerts", rule: detector.name });
  }
  for (const { rule, techniques } of GOVERNANCE_RULE_TECHNIQUES) {
    for (const t of techniques) caps.push({ techniqueId: t, module: "Agent Governance", rule });
  }

  for (const { rule, techniques } of INVESTIGATION_RULE_TECHNIQUES) {
    for (const t of techniques) caps.push({ techniqueId: t, module: "Investigations", rule });
  }

  for (const { rule, techniques } of FORENSICS_RULE_TECHNIQUES) {
    for (const t of techniques) caps.push({ techniqueId: t, module: "Email & File Forensics", rule });
  }

  // Normalize to catalog IDs (sub-techniques not in the catalog roll up).
  return caps.flatMap((c) => {
    const t = resolveTechnique(c.techniqueId);
    return t ? [{ ...c, techniqueId: t.id }] : [];
  });
}
