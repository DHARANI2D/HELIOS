import { describe, expect, it } from "vitest";

import { canonicalJson, computeEntryHash } from "@/lib/audit";
import { TACTICS, TECHNIQUES, extractTechniqueId, getTechnique, parentTechniqueId, resolveTechnique } from "@/lib/mitre/catalog";
import { maxSeverity, severityRank } from "@/lib/severity";
import { hasAnyCondition, matchesTrigger, renderTemplate, triggerConditionSchema, type CaseSnapshot } from "@/lib/playbooks/trigger";
import { DEFAULT_PLAYBOOKS } from "@/lib/playbooks/defaults";

describe("audit hashing", () => {
  it("serializes objects with recursively sorted keys", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}');
  });

  it("produces the same hash regardless of key insertion order", () => {
    const a = computeEntryHash({ actorId: "u1", caseId: null, action: "x", detail: { p: 1, q: [1, 2] }, prevHash: "GENESIS" });
    const b = computeEntryHash({ prevHash: "GENESIS", detail: { q: [1, 2], p: 1 }, action: "x", caseId: null, actorId: "u1" });
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  it("changes the hash when any field or the previous link changes", () => {
    const base = { actorId: null, caseId: "c1", action: "case.created", detail: { severity: "HIGH" }, prevHash: "abc" };
    const h = computeEntryHash(base);
    expect(computeEntryHash({ ...base, detail: { severity: "LOW" } })).not.toBe(h);
    expect(computeEntryHash({ ...base, prevHash: "abd" })).not.toBe(h);
  });
});

describe("MITRE catalog", () => {
  it("has unique technique IDs that all reference a known tactic", () => {
    const ids = TECHNIQUES.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    const tacticIds = new Set(TACTICS.map((t) => t.id));
    for (const t of TECHNIQUES) expect(tacticIds.has(t.tactic), t.id).toBe(true);
  });

  it("includes the parent of every sub-technique", () => {
    for (const t of TECHNIQUES.filter((x) => x.id.includes("."))) {
      expect(getTechnique(parentTechniqueId(t.id)!), t.id).toBeDefined();
    }
  });

  it("extracts IDs from free text and rolls unknown sub-techniques up to the parent", () => {
    expect(extractTechniqueId("T1003 - OS Credential Dumping")).toBe("T1003");
    expect(extractTechniqueId("Execution (TA0002) via T1059.001")).toBe("T1059.001");
    expect(resolveTechnique("T1566.999")?.id).toBe("T1566");
    expect(resolveTechnique("no technique here")).toBeUndefined();
  });
});

describe("severity helpers", () => {
  it("ranks and maxes severities", () => {
    expect(severityRank("CRITICAL")).toBeGreaterThan(severityRank("HIGH"));
    expect(maxSeverity("LOW", "CRITICAL", "MEDIUM")).toBe("CRITICAL");
    expect(maxSeverity()).toBe("INFO");
  });
});

describe("playbook triggers", () => {
  const snapshot: CaseSnapshot = {
    severity: "HIGH",
    sourceType: "SIEM_ALERT",
    techniqueIds: ["T1003.001", "T1078"],
    detectionSources: ["CREDENTIAL_HARVESTING"],
    riskScore: 650,
    verdict: "Malicious",
  };

  it("never matches an empty trigger", () => {
    expect(hasAnyCondition({})).toBe(false);
    expect(matchesTrigger({}, snapshot)).toBe(false);
  });

  it("applies the severity floor", () => {
    expect(matchesTrigger({ minSeverity: "HIGH" }, snapshot)).toBe(true);
    expect(matchesTrigger({ minSeverity: "CRITICAL" }, snapshot)).toBe(false);
  });

  it("matches a parent technique against its sub-techniques", () => {
    expect(matchesTrigger({ techniques: ["T1003"] }, snapshot)).toBe(true);
    expect(matchesTrigger({ techniques: ["T1486"] }, snapshot)).toBe(false);
  });

  it("requires every condition to hold", () => {
    expect(matchesTrigger({ minSeverity: "MEDIUM", sourceTypes: ["EMAIL_ANALYSIS"] }, snapshot)).toBe(false);
    expect(matchesTrigger({ detectionSources: ["CREDENTIAL_HARVESTING"], minRiskScore: 600 }, snapshot)).toBe(true);
    expect(matchesTrigger({ detectionSources: ["CREDENTIAL_HARVESTING"], minRiskScore: 700 }, snapshot)).toBe(false);
  });

  it("compares verdicts case-insensitively", () => {
    expect(matchesTrigger({ verdicts: ["malicious"] }, snapshot)).toBe(true);
    expect(matchesTrigger({ verdicts: ["benign"] }, { ...snapshot, verdict: null })).toBe(false);
  });

  it("rejects unknown keys and malformed technique IDs", () => {
    expect(triggerConditionSchema.safeParse({ severity: "HIGH" }).success).toBe(false);
    expect(triggerConditionSchema.safeParse({ techniques: ["1003"] }).success).toBe(false);
  });

  it("ships starter playbooks whose triggers are valid and non-empty", () => {
    for (const pb of DEFAULT_PLAYBOOKS) {
      const parsed = triggerConditionSchema.safeParse(pb.triggerCondition);
      expect(parsed.success, pb.name).toBe(true);
      expect(hasAnyCondition(pb.triggerCondition), pb.name).toBe(true);
    }
  });

  it("renders templates and blanks unknown variables", () => {
    expect(renderTemplate("Host {{host}} — {{ case.title }} {{missing}}", { host: "ws-1", "case.title": "Ransomware" })).toBe("Host ws-1 — Ransomware ");
  });
});
