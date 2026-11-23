// What the AI guard looks for in text going into and out of a client's AI
// application:
//   - instructions aimed at the model (prompt injection), in what a user
//     types or, indirectly, in documents and tool results it reads;
//   - attempts to take the model's rules off (jailbreaks) and to get its
//     system prompt out;
//   - personal data (with checksums where the format has one: Luhn for
//     cards, Verhoeff for Aadhaar, mod 97 for IBAN) and credentials;
//   - active content and links in answers, which the application might
//     render or follow;
//   - topics the client has ruled out, and the canary that marks a leaked
//     system prompt.
// Every detector returns spans, so the guard can mask exactly what it
// found and nothing else. Pure.

export interface Hit {
  kind: string;
  label: string;
  start: number;
  end: number;
  value: string;
}

const hitsOf = (text: string, re: RegExp, kind: string, label: string, valid: (v: string) => boolean = () => true): Hit[] => {
  const out: Hit[] = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  for (const m of text.matchAll(g)) {
    const value = m[0];
    if (!value || !valid(value)) continue;
    out.push({ kind, label, start: m.index ?? 0, end: (m.index ?? 0) + value.length, value });
  }
  return out;
};

const digits = (s: string) => s.replace(/\D/g, "");

// ---------------------------------------------------------------- checksums

export function luhn(num: string): boolean {
  const d = digits(num);
  if (d.length < 12) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

// Aadhaar numbers carry a Verhoeff check digit.
export function verhoeff(num: string): boolean {
  const d = digits(num);
  let c = 0;
  for (let i = 0; i < d.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(d[d.length - 1 - i])]];
  return c === 0;
}

export function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
    for (const c of v) rem = (rem * 10 + Number(c)) % 97;
  }
  return rem === 1;
}

// ---------------------------------------------------------------- personal data

export const PII_KINDS = {
  email: "Email addresses",
  phone: "Phone numbers",
  card: "Payment card numbers",
  aadhaar: "Aadhaar numbers",
  pan: "PAN (Indian tax ID)",
  ssn: "US Social Security numbers",
  iban: "IBAN bank accounts",
  ip: "IP addresses",
  mrn: "Medical record numbers",
  abha: "ABHA health IDs",
  dob: "Dates of birth",
} as const;
export type PiiKind = keyof typeof PII_KINDS;

const PII: Record<PiiKind, (t: string) => Hit[]> = {
  email: (t) => hitsOf(t, /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "email", "EMAIL"),
  phone: (t) => [
    ...hitsOf(t, /(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,5}){2,4}(?!\d)/, "phone", "PHONE", (v) => digits(v).length >= 9 && digits(v).length <= 15),
    ...hitsOf(t, /(?<![\w+])(?:0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/, "phone", "PHONE"),
    ...hitsOf(t, /(?<![\w+])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/, "phone", "PHONE"),
  ],
  card: (t) => hitsOf(t, /(?<![\d-])[3-6]\d{3}(?:[ -]?\d{2,4}){2,5}(?![\d-])/, "card", "CARD", (v) => digits(v).length >= 13 && digits(v).length <= 19 && luhn(v)),
  aadhaar: (t) => hitsOf(t, /(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])/, "aadhaar", "AADHAAR", (v) => digits(v).length === 12 && verhoeff(v)),
  pan: (t) => hitsOf(t, /\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b/, "pan", "PAN"),
  ssn: (t) => hitsOf(t, /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/, "ssn", "SSN"),
  iban: (t) => hitsOf(t, /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/, "iban", "IBAN", ibanValid),
  ip: (t) => hitsOf(t, /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/, "ip", "IP"),
  mrn: (t) => hitsOf(t, /\b(?:MRN|medical record (?:no\.?|number)|patient id)\s*[:#]?\s*[A-Z0-9-]{5,15}\b/i, "mrn", "MRN"),
  abha: (t) => hitsOf(t, /\b\d{2}-\d{4}-\d{4}-\d{4}\b/, "abha", "ABHA"),
  dob: (t) => hitsOf(t, /\b(?:DOB|date of birth|born on)\s*[:-]?\s*\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b/i, "dob", "DOB"),
};

export function findPii(text: string, kinds: readonly PiiKind[]): Hit[] {
  return dedupe(kinds.flatMap((k) => PII[k]?.(text) ?? []));
}

// ---------------------------------------------------------------- credentials

const SECRETS: Array<[string, RegExp]> = [
  ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b/],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Stripe live key", /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/],
  ["AI provider key", /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/],
  ["Private key", /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
  ["JSON web token", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["HELIOS token", /\b(?:hpat|hga|hgs)_[A-Za-z0-9_-]{20,}/],
  ["Connection string with password", /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?):\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+/],
];
const ASSIGNED = /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']?([^\s"',;]{8,})/gi;

export function findSecrets(text: string): Hit[] {
  const out = SECRETS.flatMap(([label, re]) => hitsOf(text, re, "secret", label));
  for (const m of text.matchAll(ASSIGNED)) {
    const value = m[2];
    if (/^\*+$|^x+$|^<.*>$|^\$\{|^REDACTED/i.test(value)) continue;
    const start = (m.index ?? 0) + m[0].lastIndexOf(value);
    out.push({ kind: "secret", label: "Password or key in clear", start, end: start + value.length, value });
  }
  return dedupe(out);
}

// ---------------------------------------------------------------- injection and jailbreaks

export type InjectionKind = "override" | "impersonation" | "extraction" | "exfiltration" | "addressed" | "hidden" | "encoded";

export const INJECTION_LABEL: Record<InjectionKind, string> = {
  override: "tries to override the assistant's instructions",
  impersonation: "imitates system or assistant messages",
  extraction: "asks for the system prompt or hidden instructions",
  exfiltration: "tells the assistant to send data somewhere",
  addressed: "is written to instruct the AI",
  hidden: "contains hidden characters",
  encoded: "hides instructions in encoded text",
};

const INJECTION: Array<[InjectionKind, RegExp]> = [
  ["override", /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|the|these|those|system)\b[^.\n]{0,30}\b(?:instructions?|rules|prompts?|guidelines|directions|guardrails|polic(?:y|ies))\b/i],
  ["override", /\b(?:new|updated|revised|real|actual) (?:system )?(?:instructions?|rules|task)\s*:/i],
  ["override", /\b(?:from now on|starting now|for the rest of (?:this|the) (?:chat|conversation)),? you (?:are|will|must|shall)\b|\byou are (?:now|no longer)\b/i],
  ["impersonation", /<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>|\[\/?INST\]|<<\/?SYS>>|^#{2,}\s*(?:system|instruction)s?\b/im],
  ["impersonation", /(?:^|\n)\s*(?:system|developer)\s*(?:prompt|message)?\s*:\s*\S/i],
  ["impersonation", /<\/?(?:system|instructions?|sys)\b[^>]*>/i],
  ["extraction", /\b(?:reveal|show|print|repeat|output|display|tell me|give me|what (?:is|are|were)|leak|dump|recite|spell out)\b[^.\n?]{0,40}\b(?:system prompt|system message|initial (?:prompt|instructions)|hidden (?:prompt|instructions|rules)|your (?:instructions|rules|system prompt|prompt|guidelines|configuration)|(?:the )?(?:text|words|prompt|everything) above)\b/i],
  ["exfiltration", /\b(?:send|post|forward|upload|email|exfiltrate|transmit)\b[^.\n]{0,60}\b(?:conversation|chat history|this (?:data|information)|the user'?s? (?:data|details|password|messages|email)|credentials|api keys?|secrets?)\b[^.\n]{0,60}\b(?:to|at)\b/i],
  ["exfiltration", /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+\?[^)\s]*=[^)\s]*\)/i],
];
// In documents and tool results (never in what a person types to the
// assistant): text addressed to the AI is itself the attack.
const ADDRESSED: RegExp[] = [
  /\b(?:dear|hey|attention|note to|message (?:for|to)|instructions? (?:for|to))\s+(?:the\s+)?(?:AI|assistant|model|LLM|chatbot|agent|copilot|chatgpt|claude)\b/i,
  /\b(?:AI|assistant|LLM|chatbot|agent|copilot)\s*[,:]\s*(?:please\s+)?(?:you must|ignore|do not|don't|always|never|instead)\b/i,
  /\bIMPORTANT\b[^.\n]{0,20}\b(?:AI|assistant|model|LLM|agent)s?\b/,
];
const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿]/;
const BASE64 = /[A-Za-z0-9+/]{32,}={0,2}/g;

const JAILBREAK: RegExp[] = [
  /\bDAN\b|\bdo anything now\b/i,
  /\b(?:developer|god|jailbreak|unrestricted|unfiltered|evil|chaos|sudo) mode\b/i,
  /\b(?:pretend|imagine|act as if|role-?play|let'?s play a game|you are an? (?:AI|assistant|model))\b[^.\n]{0,80}\b(?:no|without|free from|free of|not bound by|ignores?|unbound by) (?:any )?(?:restrictions|rules|filters|limits|guidelines|ethics|morals|polic(?:y|ies)|content polic(?:y|ies)|safety)\b/i,
  /\b(?:answer|respond|reply|talk|speak|write|act)\b[^.\n]{0,40}\b(?:without|with no|free of|ignoring) (?:any )?(?:restrictions|filters|censorship|guardrails|rules|limits|safety (?:guidelines|filters))\b/i,
  /\bhypothetical(?:ly)?\b[^.\n]{0,60}\b(?:no (?:rules|restrictions|filters)|without (?:rules|restrictions))\b/i,
  /\b(?:stay in character|you have been (?:freed|jailbroken|unlocked)|break free (?:of|from) your)\b/i,
  /\bjailbr(?:eak|oken)\b/i,
];

const clip = (text: string, start: number, end: number) => text.slice(Math.max(0, start - 30), end + 30).replace(/\s+/g, " ").trim().slice(0, 140);

function decodeBase64(s: string) {
  try {
    const text = Buffer.from(s, "base64").toString("utf8");
    return /^[\x09\x0a\x0d\x20-\x7e]+$/.test(text) ? text : null;
  } catch {
    return null;
  }
}

export interface InjectionHit {
  kind: InjectionKind;
  excerpt: string;
}

// where: "prompt" for what a person types, "content" for documents and tool
// results the model reads on the person's behalf.
export function findInjection(text: string, where: "prompt" | "content"): InjectionHit[] {
  const out: InjectionHit[] = [];
  const add = (kind: InjectionKind, excerpt: string) => {
    if (!out.some((h) => h.kind === kind)) out.push({ kind, excerpt });
  };
  for (const [kind, re] of INJECTION) {
    const m = text.match(re);
    if (m) add(kind, clip(text, m.index ?? 0, (m.index ?? 0) + m[0].length));
  }
  if (where === "content") {
    for (const re of ADDRESSED) {
      const m = text.match(re);
      if (m) add("addressed", clip(text, m.index ?? 0, (m.index ?? 0) + m[0].length));
    }
  }
  if (HIDDEN.test(text)) add("hidden", text.replace(new RegExp(HIDDEN.source, "g"), "␣").replace(/\s+/g, " ").slice(0, 140));
  for (const blob of text.match(BASE64) ?? []) {
    const decoded = decodeBase64(blob);
    if (decoded && (INJECTION.some(([, re]) => re.test(decoded)) || JAILBREAK.some((re) => re.test(decoded)))) {
      add("encoded", decoded.replace(/\s+/g, " ").slice(0, 140));
      break;
    }
  }
  return out;
}

export function findJailbreak(text: string): string | null {
  for (const re of JAILBREAK) {
    const m = text.match(re);
    if (m) return clip(text, m.index ?? 0, (m.index ?? 0) + m[0].length);
  }
  return null;
}

// ---------------------------------------------------------------- answers

const ACTIVE: Array<[string, RegExp]> = [
  ["a script tag", /<script\b/i],
  ["a javascript: link", /\bjavascript:/i],
  ["an inline event handler", /<[a-z][^>]*\son[a-z]+\s*=/i],
  ["an iframe", /<iframe\b/i],
  ["an HTML data URL", /\bdata:text\/html/i],
];

export function findActiveContent(text: string): Hit[] {
  return ACTIVE.flatMap(([label, re]) => hitsOf(text, re, "active", label));
}

export interface LinkHit extends Hit {
  host: string;
  image: boolean;
}

export function findLinks(text: string): LinkHit[] {
  const out: LinkHit[] = [];
  for (const m of text.matchAll(/(!?)\[[^\]]*\]\(\s*(https?:\/\/[^)\s]+)\s*\)|https?:\/\/[^\s)\]>"'`]+/g)) {
    const url = m[2] ?? m[0];
    let host = "";
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      continue;
    }
    out.push({ kind: "link", label: m[1] === "!" ? "image" : "link", start: m.index ?? 0, end: (m.index ?? 0) + m[0].length, value: url, host, image: m[1] === "!" });
  }
  return out;
}

export const hostAllowed = (host: string, allow: readonly string[]) => allow.some((d) => host === d.toLowerCase() || host.endsWith(`.${d.toLowerCase()}`));

export function findCanary(text: string, canary: string): boolean {
  return !!canary && text.toLowerCase().includes(canary.toLowerCase());
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function findTopics(text: string, topics: readonly string[]): string[] {
  return topics.filter((t) => t.trim().length > 1 && new RegExp(`(?<![\\w])${esc(t.trim()).replace(/\s+/g, "\\s+")}(?![\\w])`, "i").test(text));
}

const REFUSAL = /\b(?:I(?:'m| am)? (?:sorry|unable|not able)|I can(?:no|')t|I (?:won't|will not|must decline|have to decline)|(?:cannot|can't|unable to) (?:help|assist|provide|comply|share|do that|disclose|reveal)|(?:not|isn't) (?:allowed|permitted|able) to|against (?:my|the|our) (?:policy|policies|guidelines|rules)|I(?:'m| am) not (?:allowed|permitted|authori[sz]ed))\b/i;

export const isRefusal = (text: string) => REFUSAL.test(text.slice(0, 600));

// ---------------------------------------------------------------- masking

function dedupe(hits: Hit[]): Hit[] {
  const sorted = [...hits].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Hit[] = [];
  for (const h of sorted) if (!out.length || h.start >= out[out.length - 1].end) out.push(h);
  return out;
}

// Replaces each span with [REDACTED:LABEL]; overlapping spans collapse.
export function redact(text: string, hits: Hit[], label: (h: Hit) => string = (h) => h.label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")): string {
  let out = "";
  let at = 0;
  for (const h of dedupe(hits)) {
    out += text.slice(at, h.start) + `[REDACTED:${label(h)}]`;
    at = h.end;
  }
  return out + text.slice(at);
}

// Text safe to show in a finding or a log: personal data and credentials masked.
export function safeExcerpt(text: string, max = 140): string {
  const t = text.slice(0, max * 3);
  return redact(t, [...findSecrets(t), ...findPii(t, Object.keys(PII_KINDS) as PiiKind[])]).replace(/\s+/g, " ").slice(0, max);
}
