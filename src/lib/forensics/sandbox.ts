import { lookup } from "node:dns";
import { isIP } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";

import { analyzeHtml, type HtmlIntel } from "@/lib/forensics/html-intel";
import { hostOf, registrableDomain } from "@/lib/forensics/urls";
import { isPrivateIp } from "@/lib/threat-intel/indicators";
import { SANDBOX_RULES } from "@/lib/forensics/scoring";

// HTTP-level URL detonation. desas drove a real Chrome via Selenium (form
// interaction, screenshots, network capture); HELIOS fetches the URL server-
// side, follows redirects hop by hop, and inspects the landing page's HTML.
// JavaScript is NOT executed — results say so — so client-side-only
// behaviour is out of scope.
//
// Detonation reaches attacker infrastructure from the server, so every
// connection is checked against private/loopback/link-local ranges at
// connect time (not just at URL-parse time), which also defeats DNS
// rebinding to internal addresses.

const MAX_REDIRECTS = 8;
const MAX_BODY_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 10_000;

function blockedAddress(address: string): boolean {
  if (isIP(address) === 4) return isPrivateIp(address);
  // IPv6: loopback, link-local, unique-local, IPv4-mapped private
  const a = address.toLowerCase();
  if (a === "::1" || a === "::" || a.startsWith("fe80:") || a.startsWith("fc") || a.startsWith("fd")) return true;
  const mapped = a.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  return mapped ? isPrivateIp(mapped) : false;
}

const guardedAgent = new Agent({
  connect: {
    timeout: TIMEOUT_MS,
    lookup(hostname, options, callback) {
      lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) return callback(err, []);
        const list = Array.isArray(addresses) ? addresses : [{ address: addresses as unknown as string, family: 4 }];
        const blocked = list.find((a) => blockedAddress(a.address));
        if (blocked) return callback(new Error(`Refusing to connect to internal address ${blocked.address}`), []);
        callback(null, list);
      });
    },
  },
});

export interface DetonationResult {
  url: string;
  finalUrl?: string;
  status?: number;
  redirectChain: Array<{ url: string; status: number }>;
  contentType?: string;
  title?: string;
  html?: Pick<HtmlIntel, "forms" | "jsIndicators" | "passwordFields">;
  pillars: { sensitiveDataCapture: boolean; unauthorizedTarget: boolean; stealthyBehavior: boolean };
  score: number;
  reasons: string[];
  blockRecommendations: string[];
  error?: string;
  engine: "http";
}

async function readCapped(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (total < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  await reader.cancel().catch(() => undefined);
  return Buffer.concat(chunks).toString("utf8");
}

export async function detonateUrl(url: string): Promise<DetonationResult> {
  const result: DetonationResult = {
    url,
    redirectChain: [],
    pillars: { sensitiveDataCapture: false, unauthorizedTarget: false, stealthyBehavior: false },
    score: 0,
    reasons: [],
    blockRecommendations: [],
    engine: "http",
  };

  let current = url;
  try {
    const startHost = hostOf(url);
    if (!startHost || !/^https?:$/.test(new URL(url).protocol)) throw new Error("Only http(s) URLs can be detonated");
    if (isIP(startHost) && blockedAddress(startHost)) throw new Error("Refusing to detonate an internal address");

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await undiciFetch(current, {
        dispatcher: guardedAgent,
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: {
          // Phishing kits often cloak from obvious bots; look like a browser.
          "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
          accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
      });
      result.redirectChain.push({ url: current, status: res.status });
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        await res.body?.cancel().catch(() => undefined);
        current = new URL(location, current).toString();
        continue;
      }
      result.status = res.status;
      result.finalUrl = current;
      result.contentType = res.headers.get("content-type") ?? undefined;
      if (result.contentType?.includes("html") || !result.contentType) {
        const html = await readCapped(res.body as ReadableStream<Uint8Array> | null);
        const intel = analyzeHtml(html, current);
        result.title = intel.title;
        result.html = { forms: intel.forms, jsIndicators: intel.jsIndicators, passwordFields: intel.passwordFields };
        result.reasons.push(...intel.reasons.map((r) => `Sandbox (${current}): ${r}`));

        // desas's 3-pillar exfiltration model, judged statically:
        // 1 = page collects credentials / sensitive data
        // 2 = it would submit them to an off-domain target
        // 3 = stealthy behaviour (hidden forms, beacons, obfuscated JS)
        result.pillars.sensitiveDataCapture = intel.passwordFields > 0 || intel.reasons.some((r) => r.includes("sensitive field"));
        result.pillars.unauthorizedTarget = intel.forms.some((f) => f.targetType === "External");
        result.pillars.stealthyBehavior = intel.forms.some((f) => f.hidden) || intel.jsIndicators.length >= 2;
      } else {
        await res.body?.cancel().catch(() => undefined);
        if (/application\/(octet-stream|x-msdownload|zip|x-iso9660)/.test(result.contentType)) {
          result.score += 30;
          result.reasons.push(`Sandbox (${current}): URL serves a file download (${result.contentType})`);
          result.blockRecommendations.push(`Block payload URL: ${current}`);
        }
      }
      break;
    }
    if (!result.finalUrl) throw new Error(`More than ${MAX_REDIRECTS} redirects`);
  } catch (err) {
    result.error = err instanceof Error ? (err.cause instanceof Error ? `${err.message}: ${err.cause.message}` : err.message) : String(err);
  }

  // Scoring mirrors desas's calculate_sandbox_score (rules in scoring.ts).
  const rules = SANDBOX_RULES;
  const { sensitiveDataCapture: p1, unauthorizedTarget: p2, stealthyBehavior: p3 } = result.pillars;
  if (result.html && result.html.passwordFields > 0) {
    result.score += rules.passwordFieldDetected;
    result.reasons.push(`Sandbox (${result.finalUrl}): password input field (credential harvesting)`);
    result.blockRecommendations.push(`Block URL: ${result.finalUrl}`);
  }
  if (result.redirectChain.length - 1 > rules.redirectChain.minHopsToFlag) {
    result.score += rules.redirectChain.points;
    result.reasons.push(`Sandbox (${url}): long redirect chain (${result.redirectChain.length - 1} hops)`);
  }
  if (p1 && p2 && p3) {
    result.score += rules.exfiltration.allThreePillars;
    result.reasons.push(`CRITICAL (${result.finalUrl}): credential capture posting off-domain with stealthy behaviour`);
  } else if (p1 && p2) {
    result.score += rules.exfiltration.pillar1And2;
    result.reasons.push(`HIGH (${result.finalUrl}): sensitive data would be submitted to an unauthorized target`);
  } else if (p1) {
    result.score += rules.exfiltration.pillar1Only;
  } else if (p2) {
    result.score += rules.exfiltration.pillar2Only;
    result.reasons.push(`Suspicious (${result.finalUrl}): form posts to an external domain`);
  }
  if (p3 && !(p1 && p2)) result.score += rules.exfiltration.pillar3Only;
  if (result.html) result.score += rules.jsFlagPointsEach * result.html.jsIndicators.length;

  const finalHost = result.finalUrl ? hostOf(result.finalUrl) : null;
  const startHost = hostOf(url);
  if (finalHost && startHost && registrableDomain(finalHost) !== registrableDomain(startHost)) {
    result.reasons.push(`Redirected off-domain: ${startHost} → ${finalHost}`);
  }
  if (result.score >= rules.blockRecommendationThreshold) result.blockRecommendations.push(`Block entry URL: ${url}`);
  result.reasons = [...new Set(result.reasons)];
  result.blockRecommendations = [...new Set(result.blockRecommendations)];
  return result;
}
