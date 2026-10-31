import { describe, expect, it } from "vitest";

import { gaps, generateRotation, onCallAt, type Shift } from "@/lib/operations/rota";
import { qaWeight, sampleSize, weekStart, weightedSample, type QaCandidate } from "@/lib/operations/qa-sample";
import { matchScore, progressOf, runbookSchema } from "@/lib/runbooks/match";
import { RUNBOOK_TEMPLATES } from "@/lib/runbooks/templates";

const at = (s: string) => new Date(`${s}Z`);
const shift = (id: string, userId: string, from: string, to: string, extra: Partial<Shift> = {}): Shift => ({ id, userId, role: "primary", startsAt: at(from), endsAt: at(to), override: false, createdAt: at("2026-10-01T00:00:00"), ...extra });

describe("the on-call rota", () => {
  it("generates a rotation, with the next person as backup", () => {
    const r = generateRotation({ userIds: ["a", "b", "c"], from: at("2026-11-02T03:30:00"), shiftHours: 12, shifts: 4, withBackup: true });
    expect(r.filter((s) => s.role === "primary").map((s) => s.userId)).toEqual(["a", "b", "c", "a"]);
    expect(r.filter((s) => s.role === "backup").map((s) => s.userId)).toEqual(["b", "c", "a", "b"]);
    expect(r[2].startsAt.toISOString()).toBe("2026-11-02T15:30:00.000Z");
    expect(() => generateRotation({ userIds: ["a"], from: new Date(), shiftHours: 12, shifts: 2, withBackup: true })).toThrow(/two people/);
  });

  it("lets an override beat the regular shift, and finds the hours nobody covers", () => {
    const shifts = [
      shift("1", "a", "2026-11-02T00:00:00", "2026-11-02T12:00:00"),
      shift("2", "b", "2026-11-02T12:00:00", "2026-11-03T00:00:00"),
      shift("3", "c", "2026-11-02T14:00:00", "2026-11-02T16:00:00", { override: true }),
    ];
    expect(onCallAt(shifts, at("2026-11-02T13:00:00"), "primary")?.userId).toBe("b");
    expect(onCallAt(shifts, at("2026-11-02T15:00:00"), "primary")?.userId).toBe("c");
    expect(onCallAt(shifts, at("2026-11-02T15:00:00"), "backup")).toBeNull();
    const holes = gaps(shifts.slice(0, 1), at("2026-11-01T22:00:00"), at("2026-11-02T14:00:00"), "primary");
    expect(holes.map((g) => [g.from.toISOString(), g.to.toISOString()])).toEqual([
      ["2026-11-01T22:00:00.000Z", "2026-11-02T00:00:00.000Z"],
      ["2026-11-02T12:00:00.000Z", "2026-11-02T14:00:00.000Z"],
    ]);
  });
});

describe("runbooks", () => {
  const phishing = RUNBOOK_TEMPLATES.find((t) => t.title === "Phishing email")!;

  it("ships starter runbooks that pass their own schema", () => {
    for (const t of RUNBOOK_TEMPLATES) expect(runbookSchema.safeParse(t).success).toBe(true);
  });

  it("matches cases by technique (with sub-techniques), title words, source and severity", () => {
    const facts = { source: "EMAIL_ANALYSIS" as const, severity: "HIGH" as const, title: "Credential lure from look-alike domain", techniques: ["T1566.002"] };
    expect(matchScore(phishing.match, facts)).toBeGreaterThan(0);
    expect(matchScore(phishing.match, { ...facts, techniques: [] })).toBeNull();
    expect(matchScore(phishing.match, { ...facts, techniques: [], title: "Phishing reported by finance" })).toBe(1);
    // Word starts, not substrings: "phish" doesn't hit "antiphishing".
    expect(matchScore(phishing.match, { ...facts, techniques: [], title: "Antiphishing policy changed" })).toBeNull();
    expect(matchScore({ ...phishing.match, sources: ["SIEM_ALERT"] }, facts)).toBeNull();
    expect(matchScore({ ...phishing.match, minSeverity: "CRITICAL" }, facts)).toBeNull();
    expect(runbookSchema.safeParse({ ...phishing, match: { techniques: [], keywords: [] } }).success).toBe(false);
  });

  it("counts progress and the required steps still open", () => {
    const p = progressOf(phishing.steps, { confirm: { by: "A", byId: "1", at: "" }, scope: { by: "A", byId: "1", at: "", skipped: true, note: "single recipient" } });
    expect(p.done).toBe(2);
    expect(p.requiredOpen.map((s) => s.id)).toEqual(["purge", "clicked"]);
    expect(p.complete).toBe(false);
  });
});

describe("QA sampling", () => {
  const cand = (caseId: string, extra: Partial<QaCandidate> = {}): QaCandidate => ({ caseId, tenantId: "t", severity: "MEDIUM", autonomousActions: 1, aiBenign: false, newRule: false, criticalTarget: false, ...extra });

  it("weights toward high severity, new rules and critical assets, with the reasons", () => {
    expect(qaWeight(cand("a"))).toEqual({ weight: 1, reasons: ["AI acted on its own (1)"] });
    expect(qaWeight(cand("b", { severity: "CRITICAL", newRule: true, criticalTarget: true })).weight).toBe(16);
    expect(qaWeight(cand("c", { severity: "HIGH", autonomousActions: 0, aiBenign: true })).reasons).toEqual(["AI called it benign", "high severity"]);
  });

  it("takes a share with a floor, never more than there are", () => {
    expect(sampleSize(100, 10, 2)).toBe(10);
    expect(sampleSize(5, 10, 2)).toBe(2);
    expect(sampleSize(1, 10, 2)).toBe(1);
    expect(sampleSize(0, 10, 2)).toBe(0);
  });

  it("draws the same cases for the same week, and favours heavy ones", () => {
    const items = Array.from({ length: 200 }, (_, i) => ({ caseId: `c${i}`, weight: i < 20 ? 10 : 1 }));
    const a = weightedSample(items, 20, "2026-10-26");
    expect(weightedSample(items, 20, "2026-10-26")).toEqual(a);
    expect(weightedSample(items, 20, "2026-11-02")).not.toEqual(a);
    // A tenth of the cases carry over half the weight: well over a tenth of the draw.
    expect(a.filter((x) => x.weight === 10).length).toBeGreaterThan(6);
  });

  it("counts weeks from Monday, UTC", () => {
    expect(weekStart(at("2026-11-01T23:00:00")).toISOString()).toBe("2026-10-26T00:00:00.000Z");
    expect(weekStart(at("2026-11-02T00:00:00")).toISOString()).toBe("2026-11-02T00:00:00.000Z");
  });
});
