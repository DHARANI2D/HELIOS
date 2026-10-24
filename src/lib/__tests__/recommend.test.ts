import { describe, expect, it } from "vitest";

import { DEFAULT_PLAYBOOKS } from "@/lib/playbooks/defaults";
import { rankPlaybooks, type CaseTargets, type PlaybookCandidate } from "@/lib/playbooks/recommend";
import type { CaseSnapshot } from "@/lib/playbooks/trigger";

const PLAYBOOKS: PlaybookCandidate[] = DEFAULT_PLAYBOOKS.map((p, i) => ({ id: `pb${i}`, name: p.name, description: p.description, triggerCondition: p.triggerCondition, actions: p.actions.map((a) => ({ actionType: a.actionType })) }));
const NONE: CaseTargets = { hosts: [], ips: [], users: [], processes: [], hashes: [], emails: [], domains: [], agents: [] };
const snapshot = (o: Partial<CaseSnapshot>): CaseSnapshot => ({ severity: "HIGH", sourceType: "SIEM_ALERT", techniqueIds: [], detectionSources: [], riskScore: null, verdict: null, ...o });

describe("playbook recommendations", () => {
  it("puts exact trigger matches first and explains every pick", () => {
    const recs = rankPlaybooks(snapshot({ detectionSources: ["THREAT_INTEL_MATCH"] }), "Known bad ip: 185.220.101.5", { ...NONE, ips: ["185.220.101.5"] }, PLAYBOOKS);
    expect(recs[0]).toMatchObject({ name: "Block threat-intel matched IPs", exactMatch: true, noTarget: [] });
    expect(recs[0].reasons).toEqual(expect.arrayContaining(["Its trigger matches this case", "Responds to threat intel match detections"]));
  });

  it("recommends on shared techniques even when the trigger doesn't fully match", () => {
    // Ransomware technique on a MEDIUM case: below the playbook's severity bar, but still the right runbook.
    const recs = rankPlaybooks(snapshot({ severity: "MEDIUM", techniqueIds: ["T1486"] }), "Mass encryption on FILE-01", { ...NONE, hosts: ["FILE-01"] }, PLAYBOOKS);
    const ransomware = recs.find((r) => r.name.startsWith("Contain ransomware"));
    expect(ransomware).toBeDefined();
    expect(ransomware!.exactMatch).toBe(false);
    expect(ransomware!.reasons.some((r) => r.startsWith("Covers T1486"))).toBe(true);
  });

  it("says when the evidence has nothing for a step to act on", () => {
    const recs = rankPlaybooks(snapshot({ sourceType: "EMAIL_ANALYSIS", verdict: "malicious" }), "Phishing: invoice", NONE, PLAYBOOKS);
    const phishing = recs.find((r) => r.name === "Phishing response");
    expect(phishing?.noTarget).toContain("Block IP");
  });

  it("recommends nothing for an unrelated low case", () => {
    expect(rankPlaybooks(snapshot({ severity: "LOW", sourceType: "SOC_INVESTIGATION" }), "Routine logon review", NONE, PLAYBOOKS)).toEqual([]);
  });
});
