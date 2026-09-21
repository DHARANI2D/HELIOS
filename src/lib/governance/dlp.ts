// Ported from aegis's security/dlp.py SemanticFirewall + AIDLP.

const SUSPICIOUS_PATTERNS = [
  /ignore (all )?previous instructions/i,
  /system prompt/i,
  /dan mode/i,
  /jailbreak/i,
  /sudo execute/i,
  /base64 decode this/i,
  /bypass policy/i,
];

export interface FirewallResult {
  safe: boolean;
  threatType?: string;
  detectedPatterns?: string[];
}

export function scanInput(text: string): FirewallResult {
  const matches = SUSPICIOUS_PATTERNS.filter((p) => p.test(text)).map((p) =>
    p.source,
  );

  if (matches.length > 0) {
    return { safe: false, threatType: "PROMPT_INJECTION", detectedPatterns: matches };
  }
  return { safe: true };
}

const PII_PATTERNS: Record<string, RegExp> = {
  EMAIL: /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g,
  IP_ADDRESS: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  API_KEY: /(api[_-]?key|secret|token)['"]?\s*[:=]\s*['"]?([a-zA-Z0-9]{20,})['"]?/gi,
};

export interface DlpResult {
  redactedText: string;
  blockedEntities: Array<{ type: string; value: string }>;
  safe: boolean;
}

export function scanAndRedact(text: string): DlpResult {
  let redactedText = text;
  const blockedEntities: Array<{ type: string; value: string }> = [];

  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    const matches = [...text.matchAll(pattern)];
    if (matches.length > 0) {
      for (const m of matches) blockedEntities.push({ type, value: m[0] });
      redactedText = redactedText.replace(pattern, `[REDACTED_${type}]`);
    }
  }

  return { redactedText, blockedEntities, safe: blockedEntities.length === 0 };
}
