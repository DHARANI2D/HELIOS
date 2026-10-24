import type { IndicatorType } from "@prisma/client";

import { hostFromUrl } from "@/lib/threat-intel/indicators";

// Verdicts that need no provider API keys: what your own indicator store
// already knows (imported feeds, earlier provider lookups, blocks — passed
// in as an IntelSnapshot), plus desas's domain heuristics (suspicious TLDs,
// brand-impersonation keywords). Nothing here is a hardcoded list of "bad"
// addresses: an IP is only ever malicious because a feed or provider said so.

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

// Known indicators by "TYPE:value" (value lowercased), from
// threat-intel/snapshot.ts. Detectors are synchronous, so callers load the
// snapshot for a batch first and pass it in.
export type IntelSnapshot = ReadonlyMap<string, LocalVerdict>;
export const EMPTY_INTEL: IntelSnapshot = new Map();

export function intelKey(type: IndicatorType, value: string) {
  return `${type}:${value.trim().toLowerCase()}`;
}

function merge(a: LocalVerdict, b: LocalVerdict | undefined): LocalVerdict {
  if (!b) return a;
  return { score: Math.max(a.score, b.score), reasons: [...a.reasons, ...b.reasons.filter((r) => !a.reasons.includes(r))] };
}

const NONE: LocalVerdict = { score: 0, reasons: [] };

export function localVerdict(type: IndicatorType, value: string, intel: IntelSnapshot = EMPTY_INTEL): LocalVerdict {
  const known = intel.get(intelKey(type, value));
  switch (type) {
    case "IP":
    case "FILE_HASH":
      return merge(NONE, known);
    case "DOMAIN":
      return merge(scoreDomain(value), known);
    case "URL": {
      const host = hostFromUrl(value);
      const byHost = host ? merge(scoreDomain(host), intel.get(intelKey("DOMAIN", host)) ?? intel.get(intelKey("IP", host))) : NONE;
      return merge(byHost, known);
    }
    case "EMAIL_ADDRESS": {
      const domain = value.split("@")[1] ?? "";
      return merge(domain ? merge(scoreDomain(domain), intel.get(intelKey("DOMAIN", domain))) : NONE, known);
    }
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
