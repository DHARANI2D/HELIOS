import type { IndicatorType } from "@prisma/client";

// IOC extraction shared by every module — generalizes signal-fusion's
// threatIntelService.extractIndicators, desas's url_extractor, and asip's IOC
// table. Pure functions so they can be unit-tested without a database.

export interface ExtractedIndicator {
  type: IndicatorType;
  value: string;
}

// Analysts and threat reports "defang" IOCs (hxxp://evil[.]com) so they can't
// be clicked; refang before matching so both spellings resolve to one IOC.
export function refang(text: string): string {
  return text
    .replace(/h(?:xx|XX)p(s?):\/\//g, "http$1://")
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/\[@\]|\[at\]/gi, "@");
}

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}\\^`|]+/gi;
const EMAIL_RE = /\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const HASH_RE = /(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])/gi;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;

// Bare domains are only extracted for real TLDs — otherwise every
// "powershell.exe" or "invoice.docx" in a log line would become an IOC.
// Hosts inside URLs are always taken, whatever their TLD.
const KNOWN_TLDS = new Set([
  "com", "net", "org", "io", "co", "info", "biz", "us", "uk", "de", "fr", "ru", "cn", "jp", "br",
  "in", "it", "nl", "eu", "ca", "au", "es", "se", "ch", "pl", "kr", "tw", "ir", "kp", "ua", "tr",
  "gov", "edu", "mil", "int", "me", "tv", "cc", "ws", "su", "pw", "xyz", "top", "online", "site",
  "club", "live", "app", "dev", "cloud", "shop", "store", "tech", "space", "website", "icu", "buzz",
  "link", "click", "download", "review", "country", "stream", "support", "work", "tk", "ml", "ga",
  "cf", "gq", "ly", "to", "onion", "zip", "mov",
]);

export function isPrivateIp(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    a >= 224 // multicast / reserved / broadcast
  );
}

export function hostFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

export function classifyIndicator(raw: string): ExtractedIndicator | null {
  const value = refang(raw.trim());
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return { type: "URL", value };
  if (new RegExp(`^${IPV4_RE.source}$`).test(value)) return { type: "IP", value };
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) {
    return { type: "FILE_HASH", value: value.toLowerCase() };
  }
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(value)) {
    return { type: "EMAIL_ADDRESS", value: value.toLowerCase() };
  }
  if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(value)) {
    return { type: "DOMAIN", value: value.toLowerCase() };
  }
  return null;
}

export interface ExtractOptions {
  includePrivateIps?: boolean;
}

export function extractIndicators(text: string, options: ExtractOptions = {}): ExtractedIndicator[] {
  const source = refang(text);
  const seen = new Set<string>();
  const out: ExtractedIndicator[] = [];
  const add = (type: IndicatorType, value: string) => {
    const key = `${type}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ type, value });
  };

  const urlHosts = new Set<string>();
  for (const match of source.match(URL_RE) ?? []) {
    const url = match.replace(/[.,;:!?]+$/, "");
    add("URL", url);
    const host = hostFromUrl(url);
    if (host) urlHosts.add(host);
  }

  for (const ip of source.match(IPV4_RE) ?? []) {
    if (options.includePrivateIps || !isPrivateIp(ip)) add("IP", ip);
  }

  const emails = source.match(EMAIL_RE) ?? [];
  const emailDomains = new Set<string>();
  for (const email of emails) {
    const lower = email.toLowerCase();
    add("EMAIL_ADDRESS", lower);
    emailDomains.add(lower.split("@")[1]);
  }

  for (const host of urlHosts) {
    if (!new RegExp(`^${IPV4_RE.source}$`).test(host)) add("DOMAIN", host);
  }
  for (const match of source.matchAll(DOMAIN_RE)) {
    const domain = match[0].toLowerCase();
    if (!KNOWN_TLDS.has(match[1].toLowerCase())) continue;
    if (emailDomains.has(domain) && !urlHosts.has(domain)) continue;
    add("DOMAIN", domain);
  }

  for (const hash of source.match(HASH_RE) ?? []) add("FILE_HASH", hash.toLowerCase());

  return out;
}
