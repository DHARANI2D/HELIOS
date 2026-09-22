import { parse as parseTld } from "tldts";

import { enrichIndicator } from "@/lib/threat-intel/service";

// Ported from desas's analyzer/body.py analyze_body. Domain/URL reputation
// delegates to the shared Threat Intelligence service (src/lib/threat-intel)
// instead of desas's own separate VirusTotal client — one IOC cache for
// every module instead of three.

const CRED_KEYWORDS = ["password", "credential", "login", "sign in", "verify your account", "access suspended"];
const LURE_KEYWORDS = ["invoice", "payment", "overdue", "receipt", "winning", "lottery"];
const SUSPICIOUS_TLDS = ["cc", "xyz", "top", "download", "review", "country", "stream"];
const HIGH_VALUE_KEYWORDS = ["microsoft", "google", "apple", "paypal", "secure", "login", "account"];
const KNOWN_GOOD_DOMAINS = ["microsoft.com", "google.com", "apple.com", "paypal.com"];

const URL_REGEX = /https?:\/\/[^\s"'<>)]+/gi;
const PHONE_REGEX = /(?:\+?1[-. ]?)?\(?([2-9][0-8]\d)\)?[-. ]?([2-9]\d{2})[-. ]?(\d{4})/g;

export interface BodyAnalysis {
  score: number;
  reasons: string[];
  urls: string[];
  suspiciousDomains: string[];
}

export async function analyzeBody(text: string): Promise<BodyAnalysis> {
  let score = 0;
  const reasons: string[] = [];
  const textLower = text.toLowerCase();

  const credHits = CRED_KEYWORDS.filter((w) => textLower.includes(w)).length;
  if (credHits >= 2) {
    score += 15;
    reasons.push("Content suggests credential harvesting intent (login/password keywords)");
  }

  const lureHit = LURE_KEYWORDS.find((w) => textLower.includes(w));
  if (lureHit) {
    score += 5;
    reasons.push(`Financial/Lure keyword '${lureHit}' detected`);
  }

  const urls = [...new Set(text.match(URL_REGEX) ?? [])];
  const cleanUrls: string[] = [];
  const suspiciousDomains: string[] = [];

  for (const url of urls) {
    const parsed = parseTld(url);
    const domain = parsed.domain?.toLowerCase();
    if (!domain) continue;

    cleanUrls.push(url);

    if (parsed.publicSuffix && SUSPICIOUS_TLDS.includes(parsed.publicSuffix)) {
      score += 10;
      reasons.push(`Suspicious TLD '.${parsed.publicSuffix}' detected in domain ${domain}`);
      suspiciousDomains.push(domain);
    }

    const kwHit = HIGH_VALUE_KEYWORDS.find((kw) => domain.includes(kw));
    if (kwHit && !KNOWN_GOOD_DOMAINS.includes(domain)) {
      score += 15;
      reasons.push(`High-value keyword '${kwHit}' found in suspicious domain ${domain}`);
      suspiciousDomains.push(domain);
    }
  }

  // Cross-check the first few suspicious domains against the shared
  // threat-intel cache (VirusTotal, mock-backed in this environment).
  for (const domain of [...new Set(suspiciousDomains)].slice(0, 5)) {
    const indicator = await enrichIndicator("DOMAIN", domain);
    if (indicator.maliciousScore && indicator.maliciousScore > 0.3) {
      score += 50;
      reasons.push(`Threat intel: ${domain} scored ${Math.round(indicator.maliciousScore * 100)}% malicious`);
    }
  }

  const phones = [...text.matchAll(PHONE_REGEX)];
  if (phones.length > 0 && (textLower.includes("call") || textLower.includes("support") || textLower.includes("helpline"))) {
    score += 10;
    reasons.push("Potential TOAD indicator: phone numbers detected with support keywords");
  }

  return {
    score,
    reasons,
    urls: [...new Set(cleanUrls)],
    suspiciousDomains: [...new Set(suspiciousDomains)],
  };
}
