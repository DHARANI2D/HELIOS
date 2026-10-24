import type { CaseSeverity, CaseSource, DetectionSource, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { findRelatedCases } from "@/lib/cases/related";

// Everything an AI agent may base a conclusion on, with a short reference id
// per item (D3 = third detection, E12 = twelfth event, I2 = second
// indicator). Agents must cite these ids; ai/grounding checks the citations
// and every action target against the same evidence.

export interface EvidenceRef {
  ref: string;
  kind: "detection" | "event" | "indicator" | "timeline" | "context";
  text: string;
}

export interface CaseEntities {
  hosts: string[];
  users: string[];
  ips: string[];
  domains: string[];
  hashes: string[];
  emails: string[];
  processes: string[];
  agents: string[]; // governed AI agent ids and names
}

export interface CaseEvidence {
  caseId: string;
  title: string;
  summary: string | null;
  sourceType: CaseSource;
  domain: SecurityDomain | null;
  severity: CaseSeverity;
  status: string;
  verdict: string | null;
  confidence: number | null;
  riskScore: number | null;
  tenantId: string | null;
  tenantName: string | null;
  planName: string | null;
  detectionSources: DetectionSource[];
  maliciousIndicators: number;
  techniques: string[];
  refs: EvidenceRef[];
  entities: CaseEntities;
  related: Array<{ title: string; reasons: string[] }>;
}

const MAX_EVENTS = 80;
const MAX_DETECTIONS = 40;
const MAX_INDICATORS = 40;
const MAX_TIMELINE = 40;

function uniq(values: Array<string | null | undefined>) {
  return [...new Set(values.filter((v): v is string => !!v && v.trim() !== "" && v !== "unknown"))];
}

function basename(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

export async function gatherEvidence(caseId: string): Promise<CaseEvidence> {
  const kase = await db.case.findUniqueOrThrow({
    where: { id: caseId },
    include: {
      tenant: { select: { name: true, plan: { select: { name: true } } } },
      detections: { orderBy: { createdAt: "asc" }, take: MAX_DETECTIONS },
      indicators: { include: { indicator: true }, take: MAX_INDICATORS },
      mitreTechniques: { select: { techniqueId: true } },
      events: { orderBy: { timestamp: "asc" }, take: MAX_EVENTS },
      timeline: { orderBy: { occurredAt: "asc" }, take: MAX_TIMELINE },
    },
  });
  const meta = (kase.metadata ?? {}) as Record<string, unknown>;

  const refs: EvidenceRef[] = [];
  kase.detections.forEach((d, i) => {
    const ev = (d.evidence ?? {}) as Record<string, unknown>;
    const reasoning = Array.isArray(ev.reasoning) ? (ev.reasoning as string[]).slice(0, 3).join(" · ") : "";
    refs.push({ ref: `D${i + 1}`, kind: "detection", text: `[${d.severity}] ${d.title} (${d.source.toLowerCase()})${reasoning ? ` — ${reasoning}` : ""}` });
  });
  kase.indicators.forEach((ci, i) => {
    const ind = ci.indicator;
    const score = ind.maliciousScore != null ? ` reputation=${ind.maliciousScore.toFixed(2)}` : "";
    refs.push({ ref: `I${i + 1}`, kind: "indicator", text: `${ind.type} ${ind.value}${ci.role ? ` role=${ci.role}` : ""}${score}${ind.blockedAt ? " (already blocked)" : ""}` });
  });
  if (kase.events.length) {
    kase.events.forEach((e, i) => {
      const parts = [
        e.timestamp.toISOString().slice(0, 19).replace("T", " "),
        e.eventType,
        e.hostName && `host=${e.hostName}`,
        e.userName && `user=${e.userName}`,
        e.processName && `proc=${e.processName}${e.processPid != null ? `(${e.processPid})` : ""}`,
        e.parentProcessName && `parent=${e.parentProcessName}`,
        e.commandLine && e.commandLine !== e.processName && `cmd=${e.commandLine.slice(0, 200)}`,
        e.sourceIp && `src=${e.sourceIp}`,
        e.destIp && `dst=${e.destIp}${e.destPort ? `:${e.destPort}` : ""}`,
        e.filePath && `file=${e.filePath}`,
        e.fileHash && `sha256=${e.fileHash}`,
      ].filter(Boolean);
      refs.push({ ref: `E${i + 1}`, kind: "event", text: parts.join(" ") });
    });
  } else {
    kase.timeline.forEach((t, i) => {
      refs.push({ ref: `T${i + 1}`, kind: "timeline", text: `${t.occurredAt.toISOString().slice(0, 19).replace("T", " ")} ${t.action}${t.actor ? ` (${t.actor})` : ""}: ${t.detail ?? ""}`.slice(0, 300) });
    });
  }

  // Source-specific context that isn't in rows: the email headers, the
  // governed agent.
  const headers = (meta.headers ?? null) as Record<string, unknown> | null;
  if (headers) {
    const fields = ["fromAddress", "fromDisplayName", "replyTo", "returnPath", "subject", "senderIp"]
      .map((k) => (headers[k] ? `${k}=${String(headers[k]).slice(0, 120)}` : null))
      .filter(Boolean);
    if (fields.length) refs.push({ ref: "C1", kind: "context", text: `Email headers: ${fields.join(" ")}` });
  }
  if (kase.sourceType === "AGENT_GOVERNANCE") {
    refs.push({ ref: `C${refs.filter((r) => r.kind === "context").length + 1}`, kind: "context", text: `Governed AI agent ${String(meta.agentName ?? "")} (id ${kase.sourceRef}); scenario outcome: ${String(meta.outcome ?? "")}` });
  }

  const byType = (type: string) => kase.indicators.filter((ci) => ci.indicator.type === type).map((ci) => ci.indicator.value);
  const riskObject = typeof meta.riskObject === "string" ? meta.riskObject : null;
  const riskType = typeof meta.riskObjectType === "string" ? meta.riskObjectType : null;

  const entities: CaseEntities = {
    hosts: uniq([...kase.events.map((e) => e.hostName), meta.hostName as string | undefined, riskType === "host" ? riskObject : null]),
    users: uniq([...kase.events.map((e) => e.userName), meta.userName as string | undefined, riskType === "user" ? riskObject : null]),
    ips: uniq([...byType("IP"), ...kase.events.flatMap((e) => [e.sourceIp, e.destIp]), riskType === "ip" ? riskObject : null]),
    domains: uniq(byType("DOMAIN")),
    hashes: uniq([...byType("FILE_HASH"), ...kase.events.map((e) => e.fileHash)]).map((h) => h.toLowerCase()),
    emails: uniq([...byType("EMAIL_ADDRESS"), headers?.fromAddress as string | undefined]).map((e) => e.toLowerCase()),
    processes: uniq(kase.events.flatMap((e) => [e.processName && basename(e.processName), e.parentProcessName && basename(e.parentProcessName)])),
    agents: kase.sourceType === "AGENT_GOVERNANCE" ? uniq([kase.sourceRef, meta.agentName as string | undefined]) : [],
  };

  const related = (await findRelatedCases(caseId, { limit: 3 }).catch(() => [])).map((r) => ({ title: r.title, reasons: r.reasons.slice(0, 4) }));

  return {
    caseId: kase.id,
    title: kase.title,
    summary: kase.summary,
    sourceType: kase.sourceType,
    domain: kase.domain,
    severity: kase.severity,
    status: kase.status,
    verdict: kase.verdict,
    confidence: kase.confidence,
    riskScore: kase.riskScore,
    tenantId: kase.tenantId,
    tenantName: kase.tenant?.name ?? null,
    planName: kase.tenant?.plan?.name ?? null,
    detectionSources: [...new Set(kase.detections.map((d) => d.source))],
    maliciousIndicators: kase.indicators.filter((ci) => (ci.indicator.maliciousScore ?? 0) >= 0.4).length,
    techniques: kase.mitreTechniques.map((t) => t.techniqueId),
    refs,
    entities,
    related,
  };
}

export function renderEvidence(ev: CaseEvidence): string {
  const lines = (kind: EvidenceRef["kind"]) => ev.refs.filter((r) => r.kind === kind).map((r) => `${r.ref}: ${r.text}`).join("\n");
  const section = (tag: string, body: string) => (body ? `<${tag}>\n${body}\n</${tag}>` : "");
  const entity = (label: string, values: string[]) => (values.length ? `${label}: ${values.slice(0, 25).join(", ")}` : null);
  return [
    `<case id="${ev.caseId}" source="${ev.sourceType}" severity="${ev.severity}" status="${ev.status}"${ev.verdict ? ` module_verdict="${ev.verdict}"` : ""}${ev.riskScore != null ? ` risk="${Math.round(ev.riskScore)}"` : ""} client="${ev.tenantName ?? "internal"}"${ev.planName ? ` plan="${ev.planName}"` : ""}>`,
    `Title: ${ev.title}`,
    ev.summary ? `Summary: ${ev.summary.slice(0, 1500)}` : "",
    ev.techniques.length ? `ATT&CK: ${ev.techniques.join(", ")}` : "",
    "</case>",
    section("detections", lines("detection")),
    section("indicators", lines("indicator")),
    section("events", lines("event")),
    section("timeline", lines("timeline")),
    section("context", lines("context")),
    section(
      "entities",
      [entity("hosts", ev.entities.hosts), entity("users", ev.entities.users), entity("ips", ev.entities.ips), entity("domains", ev.entities.domains), entity("file hashes", ev.entities.hashes), entity("email addresses", ev.entities.emails), entity("processes", ev.entities.processes), entity("ai agents", ev.entities.agents)]
        .filter(Boolean)
        .join("\n"),
    ),
    ev.related.length
      ? `<related_cases note="Earlier cases sharing hosts, accounts or indicators. Context only — not evidence for this case.">\n${ev.related.map((r) => `- ${r.title} (${r.reasons.join("; ")})`).join("\n")}\n</related_cases>`
      : "",
  ]
    .filter(Boolean)
    .join("\n\n");
}
