import type { CaseSeverity } from "@prisma/client";

// Port of desas's core/scoring.py + scoring_rules.yaml + verdict_explainer.py.
// Point values are desas's defaults; override the verdict thresholds with
// FORENSICS_MALICIOUS_THRESHOLD / FORENSICS_SUSPICIOUS_THRESHOLD.

export const SANDBOX_RULES = {
  passwordFieldDetected: 40,
  redirectChain: { minHopsToFlag: 2, points: 10 },
  exfiltration: {
    allThreePillars: 100,
    pillar1And2: 80,
    pillar1Only: 40,
    pillar2Only: 30,
    pillar3Only: 20,
  },
  jsFlagPointsEach: 10,
  blockRecommendationThreshold: 20,
};

// desas's defaults; Settings → Forensics overrides them.
export interface VerdictThresholds {
  malicious: number;
  suspicious: number;
}
export const DEFAULT_THRESHOLDS: VerdictThresholds = { malicious: 71, suspicious: 31 };

export type Verdict = "malicious" | "suspicious" | "benign";

export interface ScoreComponent {
  component: "Header analysis" | "Content analysis" | "Attachment forensics" | "Sandbox behavior" | "Threat intel" | "Sender infrastructure";
  points: number;
  reasons: string[];
}

export interface VerdictResult {
  totalScore: number;
  verdict: Verdict;
  threatType?: string;
  threatCategory?: string;
  breakdown: ScoreComponent[];
  confidence: number; // 0-1
  explanation: string;
  severity: CaseSeverity;
}

export function aggregateVerdict(components: ScoreComponent[], thresholds: VerdictThresholds = DEFAULT_THRESHOLDS): VerdictResult {
  const breakdown = components.filter((c) => c.points > 0 || c.reasons.length > 0);
  const totalScore = breakdown.reduce((s, c) => s + c.points, 0);
  const verdict: Verdict =
    totalScore >= thresholds.malicious ? "malicious" : totalScore >= thresholds.suspicious ? "suspicious" : "benign";

  const all = breakdown.flatMap((c) => c.reasons).map((r) => r.toLowerCase());
  const any = (keys: string[]) => all.some((r) => keys.some((k) => r.includes(k)));

  let threatType: string | undefined;
  let threatCategory: string | undefined;
  if (verdict !== "benign") {
    if (any(["macro", "executable", "packed", "payload", "polyglot", "ole", "flagged by", "download"])) {
      threatType = "Malware";
      threatCategory = any(["macro"]) ? "Macro dropper" : "Payload delivery";
    } else if (any(["password", "credential", "login", "sensitive field"])) {
      threatType = "Phishing";
      threatCategory = "Credential harvesting";
    } else if (any(["toad", "callback"])) {
      threatType = "Phishing";
      threatCategory = "Callback (TOAD)";
    } else if (any(["spoof", "dmarc", "reply-to", "return-path"])) {
      threatType = "Phishing";
      threatCategory = "Sender impersonation";
    } else {
      threatType = "Suspicious activity";
      threatCategory = "Anomalous message";
    }
  }

  // verdict_explainer.calculate_confidence: evidence diversity dominates.
  const categories = breakdown.filter((c) => c.points > 0).length;
  const strong = breakdown.flatMap((c) => c.reasons).filter((r) => /critical|dmarc|macro|password|executable|malicious/i.test(r)).length;
  let confidence = 0.5 + categories * 0.1 + Math.min(strong * 0.05, 0.3);
  if (totalScore >= 150 || totalScore < 10) confidence += 0.1;
  confidence = Math.min(confidence, 0.99);

  const top = breakdown
    .filter((c) => c.points > 0)
    .sort((a, b) => b.points - a.points)
    .map((c) => `${c.component.toLowerCase()} (+${c.points})`);
  const explanation =
    verdict === "benign"
      ? `Scored ${totalScore}, below the suspicious threshold of ${thresholds.suspicious}.${top.length ? ` Minor signals from ${top.join(", ")}.` : " No risk signals fired."}`
      : `Scored ${totalScore} (${verdict} ≥ ${verdict === "malicious" ? thresholds.malicious : thresholds.suspicious}), driven by ${top.join(", ")}.${threatType ? ` Classified as ${threatType}: ${threatCategory}.` : ""}`;

  const severity: CaseSeverity =
    verdict === "malicious" ? (totalScore >= 150 ? "CRITICAL" : "HIGH") : verdict === "suspicious" ? "MEDIUM" : "LOW";

  return { totalScore, verdict, threatType, threatCategory, breakdown, confidence, explanation, severity };
}
