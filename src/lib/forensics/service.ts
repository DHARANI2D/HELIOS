import { createHash } from "node:crypto";
import type { CaseSeverity } from "@prisma/client";

import { logAction } from "@/lib/audit";
import { createCase, type NewDetection, type NewIndicator, type NewTimelineEntry } from "@/lib/cases/writer";
import { analyzeHeaders, type HeaderAnalysis } from "@/lib/forensics/headers";
import { parseMessage } from "@/lib/forensics/message";
import { analyzeBody, domainWhitelist, type BodyAnalysis } from "@/lib/forensics/body";
import { analyzeFile, riskFor, type AttachmentAnalysis } from "@/lib/forensics/files";
import { detonateUrl, type DetonationResult } from "@/lib/forensics/sandbox";
import { aggregateVerdict, type ScoreComponent, type VerdictResult } from "@/lib/forensics/scoring";
import { hostOf, registrableDomain } from "@/lib/forensics/urls";
import { localVerdict } from "@/lib/threat-intel/local-intel";
import { configuredProviders } from "@/lib/threat-intel/providers";
import { indicatorReasons, lookupIndicator } from "@/lib/threat-intel/service";
import { MX_CHECKS, mxToolboxConfigured, queryMxToolbox, type MxDiagnostics } from "@/lib/forensics/mxtoolbox";
import { loadIntelSnapshot } from "@/lib/threat-intel/snapshot";
import { getSetting } from "@/lib/settings";

// Orchestrates desas's analysis pipeline (eel_main.analyze_email): parse →
// headers → body → attachments → optional URL detonation → verdict, then
// files the result as an EMAIL_ANALYSIS case so it joins the shared case
// stream, MITRE matrix, IOC store, and playbook triggers.

const MAX_ATTACHMENTS = 50;
const MAX_DETONATIONS = 5;

export interface EmailSummary {
  format: "eml" | "msg";
  subject: string;
  from?: string;
  to?: string;
  cc?: string;
  replyTo?: string;
  date?: string;
  messageId?: string;
  bodyPreview: string;
}

export interface ForensicsMetadata {
  kind: "email" | "file";
  email?: EmailSummary;
  headers?: HeaderAnalysis;
  body?: BodyAnalysis;
  attachments: AttachmentAnalysis[];
  sandbox: DetonationResult[];
  detonationRequested: boolean;
  mxtoolbox?: MxDiagnostics | null;
  verdict: VerdictResult;
  blockRecommendations: string[];
}

function severityFor(points: number): CaseSeverity {
  if (points >= 70) return "CRITICAL";
  if (points >= 40) return "HIGH";
  if (points >= 15) return "MEDIUM";
  return "LOW";
}

const ATTACHMENT_SEVERITY: Record<AttachmentAnalysis["risk"], CaseSeverity> = {
  Malicious: "CRITICAL",
  "High Risk": "HIGH",
  Suspicious: "MEDIUM",
  Clean: "LOW",
};

function flattenAttachments(list: AttachmentAnalysis[]): AttachmentAnalysis[] {
  return list.flatMap((a) => [a, ...flattenAttachments(a.children ?? [])]);
}

// Intel on the sending infrastructure. Built-in intel always applies; with
// provider keys the sender IP is looked up synchronously (cached 24h) the way
// desas scored AbuseIPDB reputation: > 0.5 → +20, > 0.1 → +10.
async function intelComponent(headers: HeaderAnalysis | undefined, body: BodyAnalysis | undefined): Promise<ScoreComponent> {
  const reasons: string[] = [];
  let points = 0;
  if (headers?.senderIp) {
    const ip = headers.senderIp;
    const local = localVerdict("IP", ip, await loadIntelSnapshot([{ type: "IP", value: ip }]));
    let score = local.score;
    const why = [...local.reasons];
    if ((await configuredProviders()).length) {
      const { indicator } = await lookupIndicator("IP", ip);
      score = Math.max(score, indicator.maliciousScore ?? 0);
      why.push(...indicatorReasons(indicator).filter((r) => !why.includes(r)));
    }
    if (score > 0.5) {
      points += 20;
      reasons.push(`Sending IP ${ip} has a high-risk reputation (${why.join("; ")})`);
    } else if (score > 0.1) {
      points += 10;
      reasons.push(`Sending IP ${ip} has prior abuse reports (${why.join("; ")})`);
    }
  }
  const domainIntel = await loadIntelSnapshot((body?.suspiciousDomains ?? []).map((value) => ({ type: "DOMAIN" as const, value })));
  for (const domain of body?.suspiciousDomains ?? []) {
    const v = localVerdict("DOMAIN", domain, domainIntel);
    if (v.score >= 0.7) {
      points += 20;
      reasons.push(`Linked domain ${domain} matches threat intel`);
    }
  }
  return { component: "Threat intel", points: Math.min(points, 40), reasons };
}

// desas verdict_explainer.analyze_infrastructure: +5 per failed MxToolbox monitor.
function infrastructureComponent(mx: MxDiagnostics | null): ScoreComponent {
  const reasons: string[] = [];
  let points = 0;
  for (const check of MX_CHECKS) {
    const result = mx?.[check];
    if (!result?.checked || result.passed) continue;
    points += 5;
    const failed = result.details.filter((d) => d.status === "FAIL").map((d) => d.name);
    reasons.push(`MxToolbox ${check.toUpperCase()} check failed${failed.length ? `: ${failed.slice(0, 3).join(", ")}` : ""}`);
  }
  return { component: "Sender infrastructure", points, reasons };
}

export interface AnalyzeInput {
  filename: string;
  bytes: Uint8Array;
  detonate: boolean;
  actorId?: string;
  tenantId?: string | null;
}

export async function analyzeSubmission(input: AnalyzeInput) {
  const [savedDomains, thresholds] = await Promise.all([getSetting("forensics.allowDomains"), getSetting("forensics.thresholds")]);
  const whitelist = domainWhitelist(savedDomains);
  const message = await parseMessage(input.filename, input.bytes);
  const isEmail = message !== null;
  let email: EmailSummary | undefined;
  let headers: HeaderAnalysis | undefined;
  let body: BodyAnalysis | undefined;
  let attachments: AttachmentAnalysis[];
  let sentAt: Date | undefined;

  if (message) {
    email = {
      format: message.format,
      subject: message.subject,
      from: message.from,
      to: message.to,
      cc: message.cc,
      replyTo: message.replyTo,
      date: message.date?.toISOString(),
      messageId: message.messageId,
      bodyPreview: message.text.slice(0, 3000),
    };
    sentAt = message.date;
    headers = await analyzeHeaders(message.headerLines, message.subject);
    body = analyzeBody(message.text, message.html, whitelist);
    attachments = await Promise.all(
      message.attachments.slice(0, MAX_ATTACHMENTS).map(async (a) => {
        const analysis = analyzeFile(a.filename, a.content, a.contentType);
        // Attackers wrap the real payload in a forwarded mail item; open it one
        // level deep and analyze what it carries.
        const inner = a.embeddedMessage ? await parseMessage(a.filename, a.content).catch(() => null) : null;
        if (inner) {
          analysis.reasons.unshift(`Embedded email message: "${inner.subject}"${inner.from ? ` from ${inner.from}` : ""}`);
          analysis.children = inner.attachments.slice(0, MAX_ATTACHMENTS).map((c) => analyzeFile(c.filename, c.content, c.contentType, 1));
          const innerBody = analyzeBody(inner.text, inner.html, whitelist);
          analysis.urls = [...new Set([...analysis.urls, ...innerBody.urls])];
          analysis.reasons.push(...innerBody.reasons.map((r) => `Embedded message: ${r}`));
          analysis.score += innerBody.score + analysis.children.reduce((sum, c) => sum + c.score, 0);
          analysis.risk = riskFor(analysis.score);
        }
        return analysis;
      }),
    );
  } else {
    attachments = [analyzeFile(input.filename, input.bytes)];
  }

  const allFiles = flattenAttachments(attachments);
  const candidateUrls = [...new Set([...(body?.urls ?? []), ...allFiles.flatMap((a) => a.urls)])].filter((u) => {
    const host = hostOf(u);
    return host && !whitelist.some((w) => registrableDomain(host) === w);
  });

  const senderDomain = headers?.fromAddress?.split("@")[1];
  const mxtoolbox = senderDomain && (await mxToolboxConfigured()) ? await queryMxToolbox(senderDomain, headers?.dkimSelector) : null;

  const sandbox = input.detonate ? await Promise.all(candidateUrls.slice(0, MAX_DETONATIONS).map(detonateUrl)) : [];

  const verdict = aggregateVerdict([
    { component: "Header analysis", points: headers?.score ?? 0, reasons: headers?.reasons ?? [] },
    { component: "Content analysis", points: body?.score ?? 0, reasons: body?.reasons ?? [] },
    {
      component: "Attachment forensics",
      points: attachments.reduce((s, a) => s + a.score, 0),
      reasons: attachments.flatMap((a) => a.reasons.map((r) => `${a.filename}: ${r}`)),
    },
    { component: "Sandbox behavior", points: sandbox.reduce((s, r) => s + r.score, 0), reasons: sandbox.flatMap((r) => r.reasons) },
    await intelComponent(headers, body),
    infrastructureComponent(mxtoolbox),
  ], thresholds);

  const blockRecommendations = [
    ...new Set([
      ...sandbox.flatMap((r) => r.blockRecommendations),
      ...(verdict.verdict !== "benign" && headers?.fromAddress ? [`Block sender: ${headers.fromAddress}`] : []),
      ...(verdict.verdict !== "benign" && headers?.senderIp ? [`Block sending IP: ${headers.senderIp}`] : []),
      ...allFiles.filter((a) => a.risk === "Malicious" || a.risk === "High Risk").map((a) => `Block attachment hash: ${a.sha256}`),
    ]),
  ];

  const metadata: ForensicsMetadata = {
    kind: isEmail ? "email" : "file",
    email,
    headers,
    body,
    attachments,
    sandbox,
    detonationRequested: input.detonate,
    mxtoolbox,
    verdict,
    blockRecommendations,
  };

  // --- case artifacts
  const detections: NewDetection[] = [];
  if (headers && headers.score > 0) {
    detections.push({ source: "EMAIL_HEADER_AUTH", ruleId: "email:header_analysis", title: `Sender authentication / identity anomalies (+${headers.score})`, severity: severityFor(headers.score), evidence: { reasons: headers.reasons, auth: headers.auth } });
  }
  if (body && body.score > 0) {
    detections.push({ source: "EMAIL_BODY_URL", ruleId: "email:body_analysis", title: `Phishing content and link indicators (+${body.score})`, severity: severityFor(body.score), evidence: { reasons: body.reasons, urls: body.urls, suspiciousDomains: body.suspiciousDomains } });
  }
  for (const a of allFiles.filter((f) => f.score > 0)) {
    detections.push({ source: "EMAIL_ATTACHMENT_FORENSICS", ruleId: `file:${a.sha256.slice(0, 16)}`, title: `${a.filename}: ${a.risk} (+${a.score})`, severity: ATTACHMENT_SEVERITY[a.risk], evidence: { reasons: a.reasons, sha256: a.sha256, fileType: a.fileType, techniques: a.techniques } });
  }
  for (const s of sandbox.filter((r) => r.score > 0)) {
    detections.push({ source: "EMAIL_SANDBOX_DETONATION", ruleId: `sandbox:${createHash("sha256").update(s.url).digest("hex").slice(0, 16)}`, title: `Detonated ${s.url} (+${s.score})`, severity: severityFor(s.score), evidence: { reasons: s.reasons, finalUrl: s.finalUrl, pillars: s.pillars, redirectChain: s.redirectChain } });
  }

  const techniques = new Set<string>(allFiles.flatMap((a) => a.techniques));
  if (verdict.verdict !== "benign") {
    if (allFiles.some((a) => a.score >= 15)) techniques.add("T1566.001");
    if ((body?.urls.length ?? 0) > 0 && ((body?.score ?? 0) > 0 || sandbox.some((s) => s.score > 0))) {
      techniques.add("T1566.002");
      techniques.add("T1204.001");
    }
    if (sandbox.some((s) => s.pillars.sensitiveDataCapture) || body?.html?.passwordFields) techniques.add("T1598");
  }

  const indicators: NewIndicator[] = [];
  if (headers?.fromAddress) indicators.push({ type: "EMAIL_ADDRESS", value: headers.fromAddress, role: "sender" });
  if (headers?.replyTo && headers.replyTo !== headers.fromAddress) indicators.push({ type: "EMAIL_ADDRESS", value: headers.replyTo, role: "reply_to" });
  if (headers?.senderIp) indicators.push({ type: "IP", value: headers.senderIp, role: "sender_ip" });
  for (const url of candidateUrls.slice(0, 50)) {
    indicators.push({ type: "URL", value: url, role: "linked_url" });
    const host = hostOf(url);
    if (host && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) indicators.push({ type: "DOMAIN", value: host, role: "linked_domain" });
  }
  for (const a of allFiles) indicators.push({ type: "FILE_HASH", value: a.sha256, role: "attachment_sha256" });
  for (const s of sandbox) if (s.finalUrl && s.finalUrl !== s.url) indicators.push({ type: "URL", value: s.finalUrl, role: "landing_page" });

  const now = new Date();
  const timeline: NewTimelineEntry[] = [];
  for (const hop of headers?.hops ?? []) {
    const t = hop.time ? new Date(hop.time) : undefined;
    if (!t || Number.isNaN(t.getTime())) continue;
    timeline.push({
      occurredAt: t,
      actor: hop.from,
      action: "smtp.hop",
      detail: `Hop ${hop.hop}: ${hop.from}${hop.ip ? ` [${hop.ip}]` : ""}${hop.by ? ` → ${hop.by}` : ""}${hop.delaySeconds !== undefined ? ` (+${hop.delaySeconds}s)` : ""}`,
    });
  }
  if (sentAt) timeline.push({ occurredAt: sentAt, actor: headers?.fromAddress ?? null, action: "email.sent", detail: `"${email?.subject}" to ${email?.to ?? "unknown recipients"}` });
  for (const s of sandbox) {
    timeline.push({ occurredAt: now, actor: "sandbox", action: "forensics.detonated", detail: `${s.url} → ${s.finalUrl ?? s.error ?? "no response"} (score ${s.score})` });
  }
  timeline.push({ occurredAt: now, actor: "forensics-engine", action: "forensics.analyzed", detail: verdict.explanation });

  const title = isEmail ? `Email: ${email!.subject}`.slice(0, 200) : `File: ${input.filename}`.slice(0, 200);
  const kase = await createCase({
    sourceType: "EMAIL_ANALYSIS",
    title,
    summary: verdict.explanation,
    severity: verdict.severity,
    status: verdict.verdict === "benign" ? "TRIAGING" : "INVESTIGATING",
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    riskScore: verdict.totalScore,
    sourceRef: email?.messageId ?? attachments[0]?.sha256,
    metadata: JSON.parse(JSON.stringify(metadata)),
    detections,
    techniques: [...techniques],
    indicators,
    timeline,
    actorId: input.actorId,
    tenantId: input.tenantId ?? null,
  });

  await logAction({
    actorId: input.actorId,
    caseId: kase.id,
    action: "forensics.analyzed",
    detail: { kind: metadata.kind, verdict: verdict.verdict, score: verdict.totalScore, attachments: allFiles.length, detonations: sandbox.length },
  });

  return { caseId: kase.id, verdict: verdict.verdict, score: verdict.totalScore };
}
