import { resolveTxt } from "node:dns/promises";

import { isPrivateIp } from "@/lib/threat-intel/indicators";

// Port of desas's analyzer/headers.py: SPF/DKIM/DMARC/TLS from
// Authentication-Results and Received, sender-identity mismatches, urgency
// lures, and a bottom-up Received hop trace.

export interface HeaderLine {
  key: string; // lower-case header name
  value: string; // unfolded value
}

export interface AuthResults {
  spf: { status: string; details: string };
  dkim: { status: string; details: string };
  dmarc: { status: string; details: string };
  tls: { version: string; cipher: string };
}

export interface Hop {
  hop: number;
  from: string;
  by?: string;
  ip?: string;
  time?: string;
  delaySeconds?: number;
}

export interface HeaderAnalysis {
  score: number;
  reasons: string[];
  auth: AuthResults;
  dkimSelector?: string;
  dkimDomain?: string;
  hops: Hop[];
  senderIp?: string;
  fromAddress?: string;
  replyTo?: string;
  returnPath?: string;
}

const URGENCY = ["urgent", "immediate", "action required", "suspended", "verify", "expiry", "expire", "attention", "security alert", "password", "unusual sign-in"];

export function emailAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const angle = value.match(/<([^>]+@[^>]+)>/);
  const addr = angle?.[1] ?? value.match(/[^\s<>"']+@[^\s<>"']+/)?.[0];
  return addr?.toLowerCase().replace(/[>;,]$/, "");
}

const domainOf = (addr?: string) => addr?.split("@")[1];

function parseAuthResults(lines: HeaderLine[]): AuthResults {
  const results: AuthResults = {
    spf: { status: "none", details: "-" },
    dkim: { status: "none", details: "-" },
    dmarc: { status: "none", details: "-" },
    tls: { version: "Unknown", cipher: "Unknown" },
  };
  const auth = lines.filter((l) => l.key === "authentication-results" || l.key === "arc-authentication-results").map((l) => l.value).join(" ").toLowerCase();
  if (auth) {
    results.spf.status = auth.match(/\bspf=([a-z]+)/)?.[1] ?? "none";
    results.dkim.status = auth.match(/\bdkim=([a-z]+)/)?.[1] ?? "none";
    results.dmarc.status = auth.match(/\bdmarc=([a-z]+)/)?.[1] ?? "none";
    const policy = auth.match(/\bdmarc=[a-z]+\s*\((?:[^)]*\b)?p=([a-z]+)/)?.[1];
    if (policy) results.dmarc.details = `Policy: ${policy}`;
    const spfFrom = auth.match(/smtp\.mailfrom=([^\s;]+)/)?.[1];
    if (spfFrom) results.spf.details = `MAIL FROM: ${spfFrom}`;
  }
  // Received-SPF is the fallback when there's no Authentication-Results.
  if (results.spf.status === "none") {
    const received = lines.find((l) => l.key === "received-spf")?.value.toLowerCase();
    const status = received?.match(/^\s*([a-z]+)/)?.[1];
    if (status) results.spf.status = status;
  }
  return results;
}

function parseHop(value: string, index: number): Hop {
  const timeStr = value.includes(";") ? value.slice(value.lastIndexOf(";") + 1).trim() : undefined;
  const ip = value.match(/\[(\d{1,3}(?:\.\d{1,3}){3})\]/)?.[1] ?? value.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/)?.[1];
  return {
    hop: index + 1,
    from: value.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? "unknown",
    by: value.match(/\bby\s+([^\s;()]+)/i)?.[1],
    ip,
    time: timeStr,
  };
}

async function dmarcRecord(domain: string): Promise<string | undefined> {
  if (process.env.FORENSICS_DNS_LOOKUPS === "false") return undefined;
  try {
    const records = await Promise.race([
      resolveTxt(`_dmarc.${domain}`),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 2000)),
    ]);
    return records.map((r) => r.join("")).find((r) => r.startsWith("v=DMARC1"));
  } catch {
    return undefined;
  }
}

export async function analyzeHeaders(lines: HeaderLine[], subject = ""): Promise<HeaderAnalysis> {
  const get = (key: string) => lines.find((l) => l.key === key)?.value;
  const reasons: string[] = [];
  let score = 0;

  const auth = parseAuthResults(lines);
  const received = lines.filter((l) => l.key === "received").map((l) => l.value);
  for (const r of received) {
    const tls = r.match(/version=(TLS[\d.]+)/i)?.[1];
    if (tls) {
      auth.tls = { version: tls, cipher: r.match(/cipher=([A-Z0-9_-]+)/i)?.[1] ?? "Unknown" };
      break;
    }
  }

  if (["fail", "softfail"].includes(auth.spf.status)) {
    score += 25;
    reasons.push(`SPF validation failed (${auth.spf.status})`);
  }
  if (auth.dkim.status === "fail") {
    score += 25;
    reasons.push("DKIM validation failed — message integrity compromised");
  }
  if (auth.dmarc.status === "fail") {
    score += 40;
    reasons.push("DMARC validation failed — domain spoofing likely");
  }

  const dkimSig = get("dkim-signature");
  const dkimDomain = dkimSig?.match(/\bd=([^;\s]+)/)?.[1];
  const dkimSelector = dkimSig?.match(/\bs=([^;\s]+)/)?.[1];
  if (dkimSig) auth.dkim.details = `Domain: ${dkimDomain ?? "unknown"}, Selector: ${dkimSelector ?? "unknown"}`;

  const lowerSubject = subject.toLowerCase();
  const urgent = URGENCY.find((w) => lowerSubject.includes(w));
  if (urgent) {
    score += 15;
    reasons.push(`High-urgency subject: '${urgent}'`);
  }

  const fromAddress = emailAddress(get("from"));
  const replyTo = emailAddress(get("reply-to"));
  const returnPath = emailAddress(get("return-path"));
  if (replyTo && fromAddress && replyTo !== fromAddress) {
    score += 20;
    reasons.push(`Reply-To mismatch: ${replyTo} (From: ${fromAddress})`);
  }
  const fromDomain = domainOf(fromAddress);
  const returnDomain = domainOf(returnPath);
  if (fromDomain && returnDomain && fromDomain !== returnDomain && !/bounce|return/.test(returnDomain)) {
    if (!returnDomain.endsWith(fromDomain) && !fromDomain.endsWith(returnDomain)) {
      score += 15;
      reasons.push(`Return-Path domain mismatch: ${returnDomain} vs ${fromDomain}`);
    }
  }

  // Bottom-up trace: the last Received header is the first hop.
  const hops = [...received].reverse().map(parseHop);
  let lastTime: number | undefined;
  for (const hop of hops) {
    const t = hop.time ? Date.parse(hop.time) : NaN;
    if (!Number.isNaN(t)) {
      if (lastTime !== undefined) hop.delaySeconds = Math.max(0, Math.round((t - lastTime) / 1000));
      lastTime = t;
    }
  }
  const senderIp = hops.find((h) => h.ip && !isPrivateIp(h.ip))?.ip;

  if (fromDomain) {
    const record = await dmarcRecord(fromDomain);
    if (record) auth.dmarc.details = `${auth.dmarc.details === "-" ? "" : `${auth.dmarc.details} | `}DNS: ${record.slice(0, 80)}`;
  }

  return { score, reasons, auth, dkimSelector, dkimDomain, hops, senderIp, fromAddress, replyTo, returnPath };
}
