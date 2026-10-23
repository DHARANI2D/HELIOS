import { hostOf, registrableDomain, unwrapUrl } from "@/lib/forensics/urls";

// Port of desas's html_intelligence.py HTMLScanner (BeautifulSoup) using
// tolerant regexes — enough to find forms, credential fields, external form
// targets, hidden forms, meta refreshes, iframes, and obfuscated JS in email
// bodies and detonated landing pages.

export interface HtmlForm {
  action: string;
  method: string;
  targetType: "Internal" | "External";
  fields: Array<{ name: string; type: string }>;
  hidden: boolean;
}

export interface HtmlIntel {
  score: number;
  reasons: string[];
  forms: HtmlForm[];
  jsIndicators: string[];
  passwordFields: number;
  title?: string;
}

const JS_OBFUSCATION: Array<[RegExp, string]> = [
  [/\beval\s*\(/i, "Use of eval() (potential obfuscation)"],
  [/String\.fromCharCode/i, "String.fromCharCode (potential obfuscation)"],
  [/\batob\s*\(/i, "atob() Base64 decoding"],
  [/\bunescape\s*\(/i, "unescape() decoding"],
  [/\\x[0-9a-f]{2}/i, "Hex-encoded character escapes"],
];
const JS_SENSITIVE: Array<[RegExp, string]> = [
  [/document\.cookie/i, "Script accesses browser cookies"],
  [/localStorage/i, "Script accesses localStorage"],
  [/sessionStorage/i, "Script accesses sessionStorage"],
  [/(?:window\.)?location(?:\.href)?\s*=/i, "Script redirects the page"],
  [/navigator\.sendBeacon|new\s+Image\(\)\.src\s*=/i, "Background beacon to a remote endpoint"],
];
const SENSITIVE_FIELDS = ["password", "passwd", "pwd", "ssn", "socialsecurity", "creditcard", "ccnum", "cardnumber", "cvv", "cvc", "pin", "otp", "secret"];

function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
}

export function analyzeHtml(html: string, pageUrl?: string): HtmlIntel {
  const result: HtmlIntel = { score: 0, reasons: [], forms: [], jsIndicators: [], passwordFields: 0 };
  if (!html) return result;
  const pageDomain = pageUrl ? (hostOf(pageUrl) ? registrableDomain(hostOf(pageUrl)!) : undefined) : undefined;

  result.title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim().slice(0, 200);

  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    const code = m[1];
    for (const [re, msg] of JS_OBFUSCATION) {
      if (re.test(code) && !result.jsIndicators.includes(msg)) {
        result.jsIndicators.push(msg);
        result.score += 10;
      }
    }
    for (const [re, msg] of JS_SENSITIVE) {
      if (re.test(code) && !result.jsIndicators.includes(msg)) {
        result.jsIndicators.push(msg);
        result.score += 5;
      }
    }
  }

  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const [, tagAttrs, inner] = m;
    const rawAction = attr(tagAttrs, "action") ?? "";
    const action = unwrapUrl(rawAction);
    const actionHost = hostOf(action);
    // Relative actions post back to the page itself; absolute ones are
    // external unless they share the page's registrable domain.
    const external = !!actionHost && (!pageDomain || registrableDomain(actionHost) !== pageDomain);
    const style = (attr(tagAttrs, "style") ?? "").replace(/\s/g, "").toLowerCase();
    const form: HtmlForm = {
      action,
      method: (attr(tagAttrs, "method") ?? "GET").toUpperCase(),
      targetType: external ? "External" : "Internal",
      fields: [],
      hidden: style.includes("display:none") || style.includes("visibility:hidden"),
    };
    if (external) {
      result.score += 15;
      result.reasons.push(`Form data is sent to an external URL: ${action}`);
    }
    for (const input of inner.matchAll(/<(input|textarea|select)\b([^>]*)>/gi)) {
      const name = (attr(input[2], "name") ?? attr(input[2], "id") ?? "").toLowerCase();
      const type = (attr(input[2], "type") ?? (input[1].toLowerCase() === "input" ? "text" : input[1].toLowerCase())).toLowerCase();
      form.fields.push({ name, type });
      if (type === "password") result.passwordFields++;
      if (SENSITIVE_FIELDS.some((s) => name.includes(s)) || type === "password") {
        result.score += 20;
        result.reasons.push(`Form collects sensitive field '${name || type}'${external ? " and posts it to an external target" : ""}`);
      }
    }
    if (form.hidden) {
      result.score += 10;
      result.reasons.push("Hidden form (stealthy data harvesting)");
    }
    result.forms.push(form);
  }

  const refresh = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*>/i)?.[0];
  if (refresh && /url\s*=/i.test(refresh)) {
    result.score += 10;
    result.reasons.push(`Meta refresh redirect: ${attr(refresh, "content")}`);
  }
  for (const m of html.matchAll(/<iframe\b([^>]*)>/gi)) {
    const src = attr(m[1], "src");
    if (src) {
      result.score += 5;
      result.reasons.push(`Embedded iframe: ${src}`);
    }
  }

  result.reasons = [...new Set(result.reasons)];
  return result;
}
