import { describe, expect, it } from "vitest";

import { EMPTY_STATS, PROMOTION, demotionCheck, levelCap, promotionCheck, scoreActions, scoreVerdict, type AiProposal } from "@/lib/shadow/ladder";
import { decideResponse, type PolicyInput } from "@/lib/response/policy";

const ai = (over: Partial<AiProposal> = {}): AiProposal => ({ actionType: "ISOLATE_HOST", target: "WS-01", outcome: "PENDING_APPROVAL", status: "SHADOW", decidedById: null, level: 0, critical: false, ...over });

describe("scoring a closed case", () => {
  it("counts a match when people took the same action, by hand or by approving it", () => {
    const [byHand] = scoreActions([ai()], [{ actionType: "ISOLATE_HOST", target: "ws-01", status: "MANUAL_REQUIRED" }], "TRUE_POSITIVE");
    expect(byHand).toMatchObject({ agreed: true, humanOutcome: "took", falseContainment: false });
    const [approved] = scoreActions([ai({ status: "EXECUTED", decidedById: "u1", level: 2 })], [], "TRUE_POSITIVE");
    expect(approved.agreed).toBe(true);
  });

  it("flags a containment people wouldn't have done, and what the AI missed", () => {
    const scored = scoreActions(
      [ai({ outcome: "EXECUTED", critical: true }), ai({ actionType: "BLOCK_IP", target: "203.0.113.9", outcome: "SUGGESTED" })],
      [{ actionType: "DISABLE_USER", target: "jdoe", status: "EXECUTED" }, { actionType: "RELEASE_HOST", target: "WS-01", status: "FAILED" }],
      "FALSE_POSITIVE",
    );
    expect(scored[0]).toMatchObject({ agreed: false, falseContainment: true, critical: true });
    expect(scored[1]).toMatchObject({ agreed: false, falseContainment: false });
    expect(scored[2]).toMatchObject({ aiOutcome: "NONE", actionType: "DISABLE_USER", agreed: false });
    expect(scored).toHaveLength(3);
    // An automatic action left standing on a real incident was accepted; rolled back, it wasn't.
    expect(scoreActions([ai({ outcome: "EXECUTED", status: "EXECUTED", level: 4 })], [], "TRUE_POSITIVE")[0].agreed).toBe(true);
    expect(scoreActions([ai({ outcome: "EXECUTED", status: "ROLLED_BACK", level: 4 })], [], "TRUE_POSITIVE")[0]).toMatchObject({ agreed: false, falseContainment: true });
  });

  it("scores verdicts against dispositions", () => {
    expect(scoreVerdict("true_positive", "TRUE_POSITIVE")).toEqual({ agreed: true });
    expect(scoreVerdict("suspicious", "FALSE_POSITIVE")).toEqual({ agreed: false });
    expect(scoreVerdict("benign", "BENIGN_TRUE_POSITIVE")).toEqual({ agreed: true });
    expect(scoreVerdict("needs_investigation", "TRUE_POSITIVE")).toBeNull();
  });
});

describe("the autonomy ladder", () => {
  const good = { ...EMPTY_STATS, decisions: PROMOTION.minDecisions, agreed: PROMOTION.minDecisions };
  it("promotes only on enough agreeing decisions and no critical mistakes", () => {
    expect(promotionCheck(0, good)).toEqual({ eligible: true, reasons: [] });
    expect(promotionCheck(0, { ...good, decisions: 5, agreed: 5 }).eligible).toBe(false);
    expect(promotionCheck(1, { ...good, agreed: 15 }).reasons[0]).toMatch(/Agreement 75%/);
    expect(promotionCheck(2, { ...good, falseContainments: 1, criticalFalseContainments: 1 }).eligible).toBe(false);
    expect(promotionCheck(4, good).eligible).toBe(false);
  });

  it("demotes on a bad week, and to suggestions after a critical mistake", () => {
    expect(demotionCheck(3, { ...EMPTY_STATS, decisions: 10, agreed: 6 })).toMatchObject({ demote: true, to: 2 });
    expect(demotionCheck(4, { ...EMPTY_STATS, decisions: 1, agreed: 1, falseContainments: 1, criticalFalseContainments: 1 })).toMatchObject({ demote: true, to: 1 });
    expect(demotionCheck(3, { ...EMPTY_STATS, decisions: 3, agreed: 0 }).demote).toBe(false); // too few to judge
    expect(demotionCheck(1, { ...EMPTY_STATS, decisions: 10, agreed: 0 }).demote).toBe(false);
  });

  it("caps decisions by level as a policy layer", () => {
    expect([0, 1, 2, 3, 4].map(levelCap)).toEqual(["SUGGESTED", "SUGGESTED", "PENDING_APPROVAL", null, null]);
    const base: PolicyInput = { actionType: "BLOCK_IP", grounded: true, confidence: 0.95, killSwitch: false, autonomy: "AUTO_CONTAIN", allowedActions: ["BLOCK_IP"], minConfidence: 0.8, tenantCap: "AUTO_CONTAIN", autoActionsLastHour: 0, maxAutoActionsPerHour: 5 };
    expect(decideResponse({ ...base, ladder: { level: 1 } })).toMatchObject({ status: "SUGGESTED", trace: [expect.objectContaining({ layer: "ladder" })] });
    expect(decideResponse({ ...base, ladder: { level: 2 } }).status).toBe("PENDING_APPROVAL");
    expect(decideResponse({ ...base, ladder: { level: 3 } }).status).toBe("EXECUTED");
    // The ladder never loosens anything else.
    expect(decideResponse({ ...base, tenantCap: "SUGGEST", ladder: { level: 4 } }).status).toBe("SUGGESTED");
  });
});
