import { refang } from "@/lib/threat-intel/indicators";

// Port of desas's url_extractor.py + utils.decode_proofpoint_url: pull URLs
// out of text/HTML, unwrap Proofpoint URLDefense and Microsoft Safe Links so
// analysis targets the real destination, and drop schema/CDN noise.

const URL_RE = /https?:\/\/[^\s"'<>()[\]{}\\^`|]+/gi;
const HREF_RE = /\b(?:href|src|action)\s*=\s*["']([^"']+)["']/gi;

const NOISE_DOMAINS = ["w3.org", "googleapis.com", "gstatic.com", "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org", "openxmlformats.org"];

export function unwrapUrl(url: string): string {
  try {
    if (url.includes("urldefense")) {
      if (url.includes("/v3/")) {
        const m = url.match(/\/v3\/__(.+?)__;/);
        if (m) return decodeURIComponent(m[1]);
      }
      const u = new URL(url);
      const target = u.searchParams.get("u");
      if (target) {
        // v2 encodes '%' as '-' and '/' as '_'
        return url.includes("/v2/") ? decodeURIComponent(target.replace(/-/g, "%").replace(/_/g, "/")) : target;
      }
    }
    if (/safelinks\.protection\.outlook\.com/i.test(url)) {
      const target = new URL(url).searchParams.get("url");
      if (target) return target;
    }
  } catch {
    // fall through to the original URL
  }
  return url;
}

function decodeEntities(s: string) {
  return s.replace(/&amp;/g, "&").replace(/&#x2f;/gi, "/").replace(/&#47;/g, "/").replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

// Common two-label public suffixes so registrableDomain("a.b.co.uk") = "b.co.uk".
const MULTI_SUFFIXES = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "co.in", "com.br", "co.nz", "com.cn", "com.mx", "co.za"]);

export function registrableDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  return MULTI_SUFFIXES.has(lastTwo) ? parts.slice(-3).join(".") : lastTwo;
}

export function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function extractUrls(content: string): string[] {
  const text = refang(decodeEntities(content));
  const found = new Set<string>();
  const consider = (raw: string) => {
    const cleaned = unwrapUrl(raw.trim().replace(/[.,;:!?)\]]+$/, ""));
    if (!/^https?:\/\//i.test(cleaned)) return;
    const host = hostOf(cleaned);
    if (!host) return;
    if (NOISE_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) return;
    found.add(cleaned);
  };
  for (const m of text.matchAll(HREF_RE)) consider(m[1]);
  for (const m of text.match(URL_RE) ?? []) consider(m);
  return [...found];
}
