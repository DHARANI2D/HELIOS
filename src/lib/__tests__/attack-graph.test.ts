import { describe, expect, it } from "vitest";

import { assembleGraph, type GraphCase } from "@/lib/cases/attack-graph";

const kase = (id: string, hour: number, tactics: string[], severity: GraphCase["severity"] = "MEDIUM"): GraphCase => ({
  id,
  title: id,
  severity,
  status: "OPEN",
  sourceType: "SIEM_ALERT",
  createdAt: new Date(Date.UTC(2026, 9, 20, hour)),
  tenantName: null,
  tactics,
});

describe("attack graph", () => {
  const cases = [kase("phish", 8, ["TA0001"], "HIGH"), kase("dump", 9, ["TA0006"], "CRITICAL"), kase("lateral", 10, ["TA0008", "TA0002"]), kase("other", 11, ["TA0002"])];

  it("keeps only entities that tie cases together, and finds chains across tactics", () => {
    const g = assembleGraph(cases, [
      { caseId: "phish", type: "user", value: "ACME\\jdoe" },
      { caseId: "dump", type: "user", value: "acme\\JDOE" }, // same account, different case
      { caseId: "lateral", type: "host", value: "WS-7" },
      { caseId: "dump", type: "host", value: "ws-7" },
      { caseId: "other", type: "ip", value: "198.51.100.9", malicious: true },
    ]);
    expect(g.entities.map((e) => e.key).sort()).toEqual(["host:ws-7", "user:acme\\jdoe"]);
    expect(g.cases.map((c) => c.id).sort()).toEqual(["dump", "lateral", "phish"]);
    // Both chains reach a critical case; the one across more tactics ranks first.
    expect(g.chains.map((c) => c.entity.key)).toEqual(["host:ws-7", "user:acme\\jdoe"]);
    expect(g.chains[0].tactics).toEqual(["TA0002", "TA0006", "TA0008"]);
    expect(g.chains[1]).toMatchObject({ caseIds: ["phish", "dump"], tactics: ["TA0001", "TA0006"], severity: "CRITICAL" });
  });

  it("ignores generic accounts and non-addresses", () => {
    const g = assembleGraph(cases, [
      { caseId: "phish", type: "user", value: "SYSTEM" },
      { caseId: "dump", type: "user", value: "system" },
      { caseId: "phish", type: "ip", value: "127.0.0.1" },
      { caseId: "dump", type: "ip", value: "127.0.0.1" },
    ]);
    expect(g.entities).toEqual([]);
    expect(g.chains).toEqual([]);
  });

  it("does not call a shared entity a chain when one case already covers every tactic", () => {
    const broad = kase("correlated", 1, ["TA0001", "TA0002", "TA0006"], "CRITICAL");
    const g = assembleGraph([broad, kase("narrow", 2, ["TA0002"])], [
      { caseId: "correlated", type: "user", value: "admin" },
      { caseId: "narrow", type: "user", value: "admin" },
    ]);
    expect(g.entities).toHaveLength(1);
    expect(g.chains).toEqual([]);
  });

  it("does not call a shared entity a chain when every case is the same tactic", () => {
    const g = assembleGraph([kase("a", 1, ["TA0002"]), kase("b", 2, ["TA0002"])], [
      { caseId: "a", type: "hash", value: "f".repeat(64), malicious: true },
      { caseId: "b", type: "hash", value: "f".repeat(64) },
    ]);
    expect(g.entities[0]).toMatchObject({ type: "hash", malicious: true, caseIds: ["a", "b"] });
    expect(g.chains).toEqual([]);
  });
});
