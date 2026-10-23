import type { IndicatorType } from "@prisma/client";

import { hostFromUrl } from "@/lib/threat-intel/indicators";

// Built-in intelligence that works with no provider API keys configured:
// signal-fusion's SecurityPolicy.threatIntel blocklist plus desas's domain
// heuristics (suspicious TLDs, brand-impersonation keywords). Provider
// lookups (VirusTotal / AbuseIPDB) layer on top of this when keys are set.

export const KNOWN_BAD_IPS: Record<string, string> = {
  "99.88.77.66": "Known C2 infrastructure",
  "45.33.22.11": "Tor exit node",
  "103.22.11.55": "Botnet IP",
};

const KNOWN_BAD_IP_PREFIXES: Array<{ prefix: string; reason: string; score: number }> = [
  { prefix: "185.220.101.", reason: "Tor exit relay range (185.220.101.0/24)", score: 0.7 },
];

export const SUSPICIOUS_TLDS = new Set([
  "cc", "xyz", "top", "download", "review", "country", "stream", "tk", "ml", "ga", "cf", "gq", "zip", "mov",
]);

const BRAND_KEYWORDS = ["microsoft", "office365", "google", "apple", "paypal", "amazon", "secure", "login", "account", "verify"];
const BRAND_DOMAINS = new Set([
  "microsoft.com", "office365.com", "office.com", "live.com", "google.com", "apple.com", "paypal.com", "amazon.com",
]);

export interface LocalVerdict {
  score: number; // 0-1
  reasons: string[];
}

function registrableDomain(host: string): string {
  const parts = host.toLowerCase().split(".");
  return parts.slice(-2).join(".");
}

function scoreDomain(domain: string): LocalVerdict {
  const reasons: string[] = [];
  let score = 0;
  const lower = domain.toLowerCase();
  const tld = lower.split(".").pop() ?? "";
  const base = registrableDomain(lower);

  if (SUSPICIOUS_TLDS.has(tld)) {
    score = Math.max(score, 0.4);
    reasons.push(`Suspicious TLD .${tld}`);
  }
  if (!BRAND_DOMAINS.has(base)) {
    const label = base.split(".")[0];
    const hit = BRAND_KEYWORDS.find((kw) => label.includes(kw));
    if (hit) {
      score = Math.max(score, 0.5);
      reasons.push(`Brand/credential keyword "${hit}" in non-brand domain ${base}`);
    }
  }
  if ((lower.match(/-/g) ?? []).length >= 3) {
    score = Math.max(score, 0.3);
    reasons.push("Heavily hyphenated domain (common in phishing kits)");
  }
  return { score, reasons };
}

export function localVerdict(type: IndicatorType, value: string): LocalVerdict {
  switch (type) {
    case "IP": {
      const known = KNOWN_BAD_IPS[value];
      if (known) return { score: 0.9, reasons: [known] };
      const prefix = KNOWN_BAD_IP_PREFIXES.find((p) => value.startsWith(p.prefix));
      if (prefix) return { score: prefix.score, reasons: [prefix.reason] };
      return { score: 0, reasons: [] };
    }
    case "DOMAIN":
      return scoreDomain(value);
    case "URL": {
      const host = hostFromUrl(value);
      const verdict = host ? scoreDomain(host) : { score: 0, reasons: [] };
      if (host && KNOWN_BAD_IPS[host]) return { score: 0.9, reasons: [KNOWN_BAD_IPS[host]] };
      return verdict;
    }
    case "EMAIL_ADDRESS": {
      const domain = value.split("@")[1] ?? "";
      return domain ? scoreDomain(domain) : { score: 0, reasons: [] };
    }
    case "FILE_HASH":
      return { score: 0, reasons: [] };
  }
}

export type IndicatorVerdict = "malicious" | "suspicious" | "low" | "clean" | "unknown";

export function verdictForScore(score: number | null | undefined, consulted: boolean): IndicatorVerdict {
  if (score == null) return "unknown";
  if (score >= 0.7) return "malicious";
  if (score >= 0.4) return "suspicious";
  if (score > 0) return "low";
  return consulted ? "clean" : "unknown";
}
