import { describe, it, expect } from "vitest";

import { matchesTrigger } from "./engine";
import type { Case, Playbook } from "@prisma/client";

function fakePlaybook(triggerCondition: unknown): Playbook {
  return {
    id: "pb-1",
    name: "test",
    description: null,
    triggerCondition,
    enabled: true,
    autoExecute: false,
    requireApproval: true,
    priority: 0,
    createdAt: new Date(),
    updatedAt: new Date(),
  } as Playbook;
}

function fakeCase(overrides: Partial<Case>): Case {
  return {
    id: "case-1",
    sourceType: "SIEM_ALERT",
    title: "test case",
    summary: null,
    severity: "MEDIUM",
    status: "OPEN",
    confidence: null,
    verdict: null,
    riskScore: null,
    assignedToId: null,
    sourceRef: null,
    rootCauseNarrative: null,
    metadata: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    resolvedAt: null,
    ...overrides,
  } as Case;
}

describe("matchesTrigger", () => {
  it("matches when severity matches and no other condition is set", () => {
    const playbook = fakePlaybook({ severity: "CRITICAL" });
    expect(matchesTrigger(playbook, fakeCase({ severity: "CRITICAL" }))).toBe(true);
    expect(matchesTrigger(playbook, fakeCase({ severity: "LOW" }))).toBe(false);
  });

  it("matches on sourceType", () => {
    const playbook = fakePlaybook({ sourceType: "EMAIL_ANALYSIS" });
    expect(matchesTrigger(playbook, fakeCase({ sourceType: "EMAIL_ANALYSIS" }))).toBe(true);
    expect(matchesTrigger(playbook, fakeCase({ sourceType: "SIEM_ALERT" }))).toBe(false);
  });

  it("matches on a minimum risk score", () => {
    const playbook = fakePlaybook({ minRiskScore: 500 });
    expect(matchesTrigger(playbook, fakeCase({ riskScore: 600 }))).toBe(true);
    expect(matchesTrigger(playbook, fakeCase({ riskScore: 100 }))).toBe(false);
    expect(matchesTrigger(playbook, fakeCase({ riskScore: null }))).toBe(false);
  });

  it("requires every condition present in the trigger to hold (AND, not OR)", () => {
    const playbook = fakePlaybook({ severity: "CRITICAL", sourceType: "SIEM_ALERT" });
    expect(matchesTrigger(playbook, fakeCase({ severity: "CRITICAL", sourceType: "SIEM_ALERT" }))).toBe(true);
    expect(matchesTrigger(playbook, fakeCase({ severity: "CRITICAL", sourceType: "EMAIL_ANALYSIS" }))).toBe(false);
  });

  it("matches any case when the trigger condition is empty", () => {
    const playbook = fakePlaybook({});
    expect(matchesTrigger(playbook, fakeCase({}))).toBe(true);
  });

  it("matches on a MITRE technique found in case metadata", () => {
    const playbook = fakePlaybook({ mitreTechnique: "T1003" });
    expect(
      matchesTrigger(playbook, fakeCase({ metadata: { mitreTechniques: ["T1003", "T1059"] } as never })),
    ).toBe(true);
    expect(
      matchesTrigger(playbook, fakeCase({ metadata: { mitreTechniques: ["T1059"] } as never })),
    ).toBe(false);
  });
});
