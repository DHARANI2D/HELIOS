import { resolveTxt } from "node:dns/promises";

// Ported from desas's analyzer/headers.py.

export interface AuthResults {
  spf: { status: string; details: string };
  dkim: { status: string; details: string };
  dmarc: { status: string; details: string };
  tls: { version: string; cipher: string };
}

export function parseAuthResults(headers: Record<string, string[]>): AuthResults {
  const results: AuthResults = {
    spf: { status: "none", details: "-" },
    dkim: { status: "none", details: "-" },
    dmarc: { status: "none", details: "-" },
    tls: { version: "Unknown", cipher: "Unknown" },
  };

  const authHeader = (headers["authentication-results"] ?? []).join(" ").toLowerCase();
  if (!authHeader) return results;

  results.spf.status = authHeader.match(/spf=([a-z]+)/)?.[1] ?? "none";
  results.dkim.status = authHeader.match(/dkim=([a-z]+)/)?.[1] ?? "none";
  results.dmarc.status = authHeader.match(/dmarc=([a-z]+)/)?.[1] ?? "none";

  const policyMatch = authHeader.match(/\(p=([a-z]+)\)/);
  if (policyMatch) results.dmarc.details = `Policy: ${policyMatch[1]}`;

  return results;
}

function extractTlsInfo(received: string[]) {
  for (const r of received) {
    const tls = r.match(/version=(TLS[\d.]+)/i);
    const cipher = r.match(/cipher=([A-Z0-9_-]+)/i);
    if (tls) return { version: tls[1], cipher: cipher?.[1] ?? "Unknown" };
  }
  return { version: "Unknown", cipher: "Unknown" };
}

function parseAddr(headerValue: string): string {
  const match = headerValue.match(/<([^>]+)>/);
  return (match ? match[1] : headerValue).trim().toLowerCase();
}

export interface Hop {
  hop: number;
  from: string;
  ip: string;
  time: string;
  delay: string;
}

export interface HeaderAnalysis {
  score: number;
  reasons: string[];
  dkimSelector: string | null;
  hops: Hop[];
  authResults: AuthResults;
}

const URGENCY_KEYWORDS = [
  "urgent",
  "immediate",
  "action required",
  "suspended",
  "verify",
  "expiry",
  "expire",
  "attention",
  "security alert",
];

export async function analyzeHeaders(headers: Record<string, string[]>): Promise<HeaderAnalysis> {
  let score = 0;
  const reasons: string[] = [];

  const received = headers["received"] ?? [];
  const authResults = parseAuthResults(headers);
  authResults.tls = extractTlsInfo(received);

  if (["fail", "softfail"].includes(authResults.spf.status)) {
    score += 25;
    reasons.push(`SPF Validation Failed (${authResults.spf.status})`);
  }
  if (authResults.dkim.status === "fail") {
    score += 25;
    reasons.push("DKIM Validation Failed - Message integrity compromised");
  }
  if (authResults.dmarc.status === "fail") {
    score += 40;
    reasons.push("DMARC Validation Failed - Domain Spoofing likely");
  }

  let dkimSelector: string | null = null;
  const dkimSig = headers["dkim-signature"]?.[0];
  if (dkimSig) {
    const d = dkimSig.match(/d=([^;]+)/);
    const s = dkimSig.match(/s=([^;]+)/);
    if (s) dkimSelector = s[1].trim();
    authResults.dkim.details = `Domain: ${d?.[1] ?? "Unknown"}, Selector: ${dkimSelector}`;
  }

  const subject = (headers["subject"]?.[0] ?? "").toLowerCase();
  const urgencyHit = URGENCY_KEYWORDS.find((w) => subject.includes(w));
  if (urgencyHit) {
    score += 15;
    reasons.push(`High Urgency Subject: '${urgencyHit}' detected`);
  }

  const fromEmail = parseAddr(headers["from"]?.[0] ?? "");
  const replyEmail = parseAddr(headers["reply-to"]?.[0] ?? "");
  const returnEmail = parseAddr(headers["return-path"]?.[0] ?? "");

  if (replyEmail && fromEmail && replyEmail !== fromEmail) {
    score += 20;
    reasons.push(`Reply-To Mismatch: ${replyEmail} (From: ${fromEmail})`);
  }

  if (returnEmail && fromEmail) {
    const fromDomain = fromEmail.split("@").pop() ?? "";
    const returnDomain = returnEmail.split("@").pop() ?? "";
    if (
      fromDomain !== returnDomain &&
      !returnDomain.includes("bounce") &&
      !returnDomain.includes("return") &&
      !returnDomain.endsWith(fromDomain) &&
      !fromDomain.endsWith(returnDomain)
    ) {
      score += 15;
      reasons.push(`Return-Path Domain Mismatch: ${returnDomain} vs ${fromDomain}`);
    }
  }

  const hops: Hop[] = [];
  const receivedReversed = [...received].reverse();
  let lastTime: Date | null = null;

  receivedReversed.forEach((r, i) => {
    const parts = r.split(";");
    const timestampStr = parts.length > 1 ? parts[parts.length - 1].trim() : "";
    let delay = 0;
    if (timestampStr) {
      const currentTime = new Date(timestampStr);
      if (!Number.isNaN(currentTime.getTime())) {
        if (lastTime) delay = Math.max(0, Math.round((currentTime.getTime() - lastTime.getTime()) / 1000));
        lastTime = currentTime;
      }
    }

    const ipMatch = r.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) ?? r.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    hops.push({
      hop: i + 1,
      from: r.split(/\s+/)[1] ?? "unknown",
      ip: ipMatch?.[1] ?? "unknown",
      time: timestampStr,
      delay: i > 0 ? `${delay}s` : "*",
    });
  });

  if (fromEmail.includes("@")) {
    const domain = fromEmail.split("@").pop()!;
    try {
      const records = await resolveTxt(`_dmarc.${domain}`);
      const dmarcRecord = records.flat().find((r) => r.includes("v=DMARC1"));
      if (dmarcRecord) authResults.dmarc.details += ` | DNS: ${dmarcRecord.slice(0, 50)}...`;
    } catch {
      // no DMARC record, or DNS unreachable from this environment — non-fatal
    }
  }

  return { score, reasons, dkimSelector, hops, authResults };
}
