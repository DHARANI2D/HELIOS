// Ported from desas's core/scoring.py — the analyst-tunable YAML rules
// file is dropped in favor of a hardcoded constant (consolidate-and-trim:
// no per-analyst rule editing UI exists yet), keeping the same default
// values and verdict thresholds.

export const SCORING_RULES = {
  verdict: {
    maliciousThreshold: 71,
    suspiciousThreshold: 31,
  },
  sandbox: {
    passwordFieldDetected: 40,
    redirectChain: { minHopsToFlag: 2, points: 10 },
    genericPostFallback: 20,
    jsFlagPointsEach: 10,
    blockRecommendationThreshold: 20,
  },
  attachment: {
    highEntropy: 20,
    oleAnomaly: 50,
    xlmMacro: 45,
    polyglot: 40,
    pdfJsOrLaunch: 35,
    vbaAutoExecWithCalls: 30,
  },
};

export interface ScoreComponent {
  component: string;
  points: number;
  reason: string;
}

export type Verdict = "malicious" | "suspicious" | "benign";

export function deriveVerdict(totalScore: number): Verdict {
  if (totalScore >= SCORING_RULES.verdict.maliciousThreshold) return "malicious";
  if (totalScore >= SCORING_RULES.verdict.suspiciousThreshold) return "suspicious";
  return "benign";
}

const MALICIOUS_KEYWORDS = ["malicious", "flagged by", "macro", "trojan", "virus", "ransomware"];
const PHISHING_KEYWORDS = ["password", "credential", "login", "young", "newly registered"];

export function classifyThreat(reasons: string[]): { threatType: string; threatCategory: string } | null {
  const lowerReasons = reasons.map((r) => r.toLowerCase());
  const hasPhish = lowerReasons.some((r) => PHISHING_KEYWORDS.some((k) => r.includes(k)));
  const hasMal = lowerReasons.some((r) => MALICIOUS_KEYWORDS.some((k) => r.includes(k)));

  if (hasPhish) {
    const credCategory = lowerReasons.some((r) => ["password", "credential", "login"].some((k) => r.includes(k)));
    return {
      threatType: "Phishing",
      threatCategory: credCategory ? "Credential Harvesting" : "Social Engineering",
    };
  }
  if (hasMal) {
    return { threatType: "Malware", threatCategory: "Payload/Dropper" };
  }
  return null;
}
