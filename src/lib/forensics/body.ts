import { analyzeHtml, type HtmlIntel } from "@/lib/forensics/html-intel";
import { extractUrls, hostOf, registrableDomain } from "@/lib/forensics/urls";

// Port of desas's analyzer/body.py: lure-language scoring, URL extraction,
// domain heuristics (suspicious TLDs, brand keywords in look-alike domains),
// TOAD (telephone-oriented attack delivery), and HTML intelligence.

export interface BodyAnalysis {
  score: number;
  reasons: string[];
  urls: string[];
  suspiciousDomains: string[];
  whitelistedHits: string[];
  html?: HtmlIntel;
}

const SUSPICIOUS_TLDS = ["cc", "xyz", "top", "download", "review", "country", "stream", "zip", "mov", "tk", "ml", "ga", "cf", "gq"];
// Brand names are flagged anywhere in a non-brand host (subdomain tricks like
// login-microsoft365.evil.xyz); generic words only in the registered label,
// since "secure."/"login." subdomains of legitimate sites are common.
const BRAND_NAMES = ["microsoft", "office365", "outlook", "google", "apple", "paypal", "amazon", "docusign"];
const GENERIC_KEYWORDS = ["secure", "login", "account", "verify"];
const BRAND_DOMAINS = new Set(["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "google.com", "apple.com", "paypal.com", "amazon.com", "docusign.com", "docusign.net"]);
const CRED_KEYWORDS = ["password", "credential", "login", "log in", "sign in", "verify your account", "access suspended", "confirm your identity", "mailbox"];
const LURE_KEYWORDS = ["invoice", "payment", "overdue", "receipt", "wire transfer", "remittance", "winning", "lottery", "gift card"];

// desas's default whitelist plus FORENSICS_DOMAIN_WHITELIST and the domains
// saved under Settings → Forensics.
export function domainWhitelist(saved: string[] = []): string[] {
  const extra = (process.env.FORENSICS_DOMAIN_WHITELIST ?? "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  return [...new Set(["google.com", "microsoft.com", "office.com", "live.com", ...extra, ...saved])];
}

export function analyzeBody(text: string, html: string | undefined, whitelist = domainWhitelist()): BodyAnalysis {
  const reasons: string[] = [];
  let score = 0;
  const content = `${text}\n${html ?? ""}`;
  const lower = content.toLowerCase();

  let htmlIntel: HtmlIntel | undefined;
  if (html && /<(html|body|form|script|a)\b/i.test(html)) {
    htmlIntel = analyzeHtml(html);
    score += htmlIntel.score;
    reasons.push(...htmlIntel.reasons, ...htmlIntel.jsIndicators.map((j) => `Security alert (JS): ${j}`));
  }

  if (CRED_KEYWORDS.filter((k) => lower.includes(k)).length >= 2) {
    score += 15;
    reasons.push("Content suggests credential-harvesting intent (login/password language)");
  }
  const lure = LURE_KEYWORDS.find((k) => lower.includes(k));
  if (lure) {
    score += 5;
    reasons.push(`Financial lure keyword '${lure}'`);
  }

  const urls: string[] = [];
  const suspiciousDomains = new Set<string>();
  const whitelistedHits = new Set<string>();
  for (const url of extractUrls(content)) {
    const host = hostOf(url);
    if (!host) continue;
    const domain = registrableDomain(host);
    if (whitelist.some((w) => domain === w || domain.endsWith(`.${w}`))) {
      whitelistedHits.add(domain);
      continue; // desas: strict skip — whitelisted domains aren't analyzed
    }
    urls.push(url);
    const tld = domain.split(".").pop() ?? "";
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 10;
      reasons.push(`Suspicious TLD '.${tld}' in ${domain}`);
      suspiciousDomains.add(domain);
    }
    if (!BRAND_DOMAINS.has(domain)) {
      const label = domain.split(".")[0];
      const kw = BRAND_NAMES.find((k) => host.includes(k)) ?? GENERIC_KEYWORDS.find((k) => label.includes(k));
      if (kw) {
        score += 15;
        reasons.push(`Brand/credential keyword '${kw}' in look-alike domain ${host}`);
        suspiciousDomains.add(domain);
      }
    }
    if (/^https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(url)) {
      score += 10;
      reasons.push(`Link points at a raw IP address: ${host}`);
      suspiciousDomains.add(host);
    }
  }

  if (/(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}/.test(content) && /\b(call|support|helpline|help desk|cancel)\b/i.test(content)) {
    score += 10;
    reasons.push("Potential TOAD lure: phone number alongside support/callback language");
  }

  return {
    score,
    reasons: [...new Set(reasons)],
    urls: [...new Set(urls)],
    suspiciousDomains: [...suspiciousDomains],
    whitelistedHits: [...whitelistedHits],
    html: htmlIntel,
  };
}
