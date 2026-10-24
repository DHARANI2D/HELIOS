import { createHash, randomUUID } from "node:crypto";
import { unzipSync, type Unzipped } from "fflate";
import type { CaseSeverity, Prisma, SecurityEvent } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { appendToCase, createCase, type NewIndicator } from "@/lib/cases/writer";
import { findRelatedCases } from "@/lib/cases/related";
import { extractIndicators, isPrivateIp } from "@/lib/threat-intel/indicators";
import { parseEvtxEvents, parseRecords, parseTelemetry, type ParseResult, type UesEvent } from "@/lib/investigations/normalize";
import { isEvtx, parseEvtx } from "@/lib/investigations/evtx";
import { isXlsx, readXlsx } from "@/lib/investigations/xlsx";
import { extractZip, readZipDirectory } from "@/lib/archive/zip";
import { buildEntityGraph, type EntityGraph } from "@/lib/investigations/graph";
import {
  describeEvent,
  heuristicQa,
  heuristicRca,
  heuristicReport,
  heuristicTriage,
  runForensicRules,
  type Finding,
  type PriorCase,
  type QaResult,
  type RcaResult,
  type TriageResult,
} from "@/lib/investigations/heuristics";
import { buildEvidence, qaAgent, rcaAgent, reportAgent, triageAgent } from "@/lib/investigations/agents";
import { resolveProvider } from "@/lib/ai/resolve";
import type { LlmProvider } from "@/lib/ai/provider";
import { loadIntelSnapshot } from "@/lib/threat-intel/snapshot";

// Orchestrates an investigation as a SOC_INVESTIGATION case: intake →
// normalize → entity graph → triage → RCA ⇄ QA (≤3 rounds, as in asip's
// route_after_qa) → report. Progress lives in case.metadata.pipeline so the
// UI can poll it while the pipeline runs in the background.

const MAX_QA_ITERATIONS = 3;
const MAX_FILE_BYTES = 20 * 1024 * 1024;
const MAX_EVENTS = 50_000;
const MAX_STORED_GRAPH_NODES = 400;

export type StageName = "triage" | "rca" | "qa" | "report";
// "claude" = Anthropic API, "local" = an OpenAI-compatible model server.
export type PipelineEngine = "claude" | "local" | "heuristic";
export interface PipelineStage {
  name: StageName;
  status: "pending" | "running" | "done" | "failed";
  engine?: PipelineEngine;
  note?: string;
  finishedAt?: string;
}

export interface InvestigationMetadata {
  pipeline: {
    status: "queued" | "running" | "completed" | "failed";
    engine: PipelineEngine;
    engineName?: string;
    model?: string;
    stages: PipelineStage[];
    qaIterations: number;
    startedAt: string;
    finishedAt?: string;
    error?: string;
  };
  input: { alertDetails: string; files: Array<{ name: string; platform: string; events: number }>; eventCount: number };
  triage?: TriageResult;
  rca?: RcaResult;
  qa?: QaResult;
  report?: string;
  graph?: EntityGraph & { truncated?: boolean; totalNodes?: number };
  findings?: Array<Pick<Finding, "ruleId" | "title" | "severity" | "techniques" | "description"> & { eventCount: number }>;
}

// --- intake ----------------------------------------------------------------

export interface IntakeFile {
  name: string;
  bytes: Uint8Array;
}

const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });

function looksBinary(bytes: Uint8Array) {
  const sample = bytes.subarray(0, 4096);
  let nul = 0;
  for (const b of sample) if (b === 0) nul++;
  return nul > sample.length * 0.01;
}

export interface ParsedSource extends ParseResult {
  name: string;
}

const TIME_COLUMN = /time|date|timestamp|^_time$|^ts$|utctime|created|when/i;

// Uncompressed size cap per archive member, so a small ZIP can't expand
// into gigabytes in memory.
const MAX_MEMBER_BYTES = 200 * 1024 * 1024;

function unzipBounded(bytes: Uint8Array, name: string, skipped: string[]) {
  return unzipSync(bytes, {
    filter: (f) => {
      if (f.originalSize <= MAX_MEMBER_BYTES) return true;
      skipped.push(`${name}/${f.name} (over ${MAX_MEMBER_BYTES / 1024 / 1024} MB uncompressed)`);
      return false;
    },
  });
}

// Password-protected archives (ZipCrypto or AES) open with the analyst's
// password; members it doesn't open are reported, not dropped silently.
function openZip(bytes: Uint8Array, name: string, skipped: string[], passwords: string[]): Unzipped {
  if (!readZipDirectory(bytes).some((m) => m.encrypted)) return unzipBounded(bytes, name, skipped);
  const r = extractZip(bytes, { passwords, maxMemberBytes: MAX_MEMBER_BYTES });
  for (const l of r.locked) skipped.push(`${name}/${l.name} (${l.reason === "no-password" ? "password-protected — enter the archive password" : "wrong archive password"})`);
  for (const s of r.skipped) skipped.push(`${name}/${s}`);
  return r.files as Unzipped; // same bytes; fflate's type pins the buffer generic
}

// Binary formats parsed directly: Windows event logs and Excel workbooks.
function parseBinary(name: string, bytes: Uint8Array, entries: Unzipped | null, skipped: string[]): ParsedSource[] | null {
  if (isEvtx(bytes)) {
    const res = parseEvtx(bytes, { maxEvents: MAX_EVENTS + 1 });
    if (res.errors.length) skipped.push(`${name} (${res.errors.length} damaged record${res.errors.length === 1 ? "" : "s"} skipped: ${res.errors[0]})`);
    return [{ name, ...parseEvtxEvents(res.events) }];
  }
  if (entries && isXlsx(entries)) {
    // Only sheets that read as event logs: rows with a time column. A notes
    // or summary sheet would otherwise become events stamped "now".
    const sources: ParsedSource[] = [];
    for (const sheet of readXlsx(entries)) {
      if (sheet.rows.length === 0) continue;
      const columns = new Set(sheet.rows.flatMap((r) => Object.keys(r)));
      if (![...columns].some((c) => TIME_COLUMN.test(c))) {
        skipped.push(`${name} › ${sheet.name} (no time column)`);
        continue;
      }
      sources.push({ name: `${name} › ${sheet.name}`, ...parseRecords(sheet.rows) });
    }
    return sources;
  }
  return null;
}

// asip's IntakeGateway recursively extracted ZIP/7z (prompting for archive
// passwords). Here: ZIPs are expanded one level, password-protected ones
// with the passwords given; EVTX and XLSX are parsed from their binary form,
// anywhere; locked or unknown binary members are reported back rather than
// silently skipped.
export function expandIntake(files: IntakeFile[], options: { passwords?: string[] } = {}): { texts: Array<{ name: string; text: string }>; parsed: ParsedSource[]; skipped: string[] } {
  const passwords = options.passwords ?? [];
  const texts: Array<{ name: string; text: string }> = [];
  const parsed: ParsedSource[] = [];
  const skipped: string[] = [];

  const take = (name: string, bytes: Uint8Array) => {
    const zipped = bytes[0] === 0x50 && bytes[1] === 0x4b;
    let entries: Unzipped | null = null;
    if (zipped) {
      try {
        entries = openZip(bytes, name, skipped, passwords);
      } catch (err) {
        skipped.push(`${name} (cannot extract: ${err instanceof Error ? err.message : "invalid archive"})`);
        return;
      }
    }
    const binary = parseBinary(name, bytes, entries, skipped);
    if (binary) {
      parsed.push(...binary);
      return;
    }
    if (entries) {
      for (const [member, data] of Object.entries(entries)) {
        if (member.endsWith("/")) continue;
        const memberName = `${name}/${member}`;
        const nested = data[0] === 0x50 && data[1] === 0x4b ? (() => { try { return openZip(data, memberName, skipped, passwords); } catch { return null; } })() : null;
        const inner = parseBinary(memberName, data, nested, skipped);
        if (inner) parsed.push(...inner);
        else if (looksBinary(data)) skipped.push(`${memberName} (unsupported binary format)`);
        else texts.push({ name: memberName, text: TEXT_DECODER.decode(data) });
      }
      return;
    }
    if (looksBinary(bytes)) skipped.push(`${name} (unsupported binary format)`);
    else texts.push({ name, text: TEXT_DECODER.decode(bytes) });
  };

  for (const file of files) {
    if (file.bytes.byteLength > MAX_FILE_BYTES) {
      skipped.push(`${file.name} (over ${MAX_FILE_BYTES / 1024 / 1024} MB)`);
      continue;
    }
    take(file.name, file.bytes);
  }
  return { texts, parsed, skipped };
}

const AUTH_TYPES = new Set(["auth", "auth_failure", "auth_explicit", "credential_validation", "logoff", "privileged_logon", "kerberos_tgt", "kerberos_service_ticket", "account_locked"]);
const SOURCE_FOR_TYPE = (eventType: string) =>
  AUTH_TYPES.has(eventType) ? "auth" : eventType.startsWith("network") || eventType === "dns_query" ? "network" : "endpoint";

function toRow(e: UesEvent, caseId: string, batchId: string): Prisma.SecurityEventCreateManyInput {
  return {
    caseId,
    batchId,
    timestamp: e.timestamp,
    source: SOURCE_FOR_TYPE(e.eventType),
    platform: e.platform,
    eventType: e.eventType,
    userName: e.userName,
    hostName: e.hostName,
    processName: e.processName,
    processPid: e.processPid,
    parentProcessName: e.parentProcessName,
    parentProcessPid: e.parentProcessPid,
    commandLine: e.commandLine,
    sourceIp: e.hostIp,
    destIp: e.dstIp,
    destPort: e.dstPort,
    filePath: e.filePath,
    fileHash: e.fileHash,
    metadata: JSON.parse(JSON.stringify({ query: e.query, raw: e.raw })),
  };
}

export function fromRow(row: SecurityEvent): UesEvent {
  const meta = (row.metadata ?? {}) as { query?: string; raw?: Record<string, unknown> };
  return {
    timestamp: row.timestamp,
    platform: row.platform ?? "unknown",
    eventType: row.eventType,
    hostName: row.hostName ?? undefined,
    hostIp: row.sourceIp ?? undefined,
    userName: row.userName ?? undefined,
    processName: row.processName ?? undefined,
    processPid: row.processPid ?? undefined,
    parentProcessName: row.parentProcessName ?? undefined,
    parentProcessPid: row.parentProcessPid ?? undefined,
    commandLine: row.commandLine ?? undefined,
    filePath: row.filePath ?? undefined,
    fileHash: row.fileHash ?? undefined,
    dstIp: row.destIp ?? undefined,
    dstPort: row.destPort ?? undefined,
    query: meta.query,
    raw: meta.raw ?? {},
  };
}

export interface StartInvestigationInput {
  title: string;
  alertDetails: string;
  files: IntakeFile[];
  pastedLogs?: string;
  actorId?: string;
  tenantId?: string | null;
  // For password-protected ZIPs; tried, never stored.
  archivePasswords?: string[];
}

async function pipelineEngine() {
  const provider = await resolveProvider("investigation");
  const engine: PipelineEngine = !provider ? "heuristic" : provider.kind === "anthropic" ? "claude" : "local";
  return { engine, engineName: provider?.name, model: provider?.model };
}

export async function startInvestigation(input: StartInvestigationInput) {
  const { texts, parsed: binary, skipped } = expandIntake(input.files, { passwords: input.archivePasswords });
  if (input.pastedLogs?.trim()) texts.push({ name: "pasted-logs", text: input.pastedLogs });

  const parsed = [...binary, ...texts.map((t) => ({ name: t.name, ...parseTelemetry(t.text, t.name) }))];
  const events = parsed.flatMap((p) => p.events);
  if (events.length === 0) {
    throw new Error(skipped.length ? `No parsable events. Skipped: ${skipped.join("; ")}` : "No parsable events in the supplied logs");
  }
  if (events.length > MAX_EVENTS) throw new Error(`Too many events (${events.length}); the limit is ${MAX_EVENTS}`);

  const { engine, engineName, model } = await pipelineEngine();
  const metadata: InvestigationMetadata = {
    pipeline: {
      status: "queued",
      engine,
      engineName,
      model,
      stages: (["triage", "rca", "qa", "report"] as StageName[]).map((name) => ({ name, status: "pending" })),
      qaIterations: 0,
      startedAt: new Date().toISOString(),
    },
    input: {
      alertDetails: input.alertDetails,
      files: parsed.map((p) => ({ name: p.name, platform: p.platform, events: p.events.length })),
      eventCount: events.length,
    },
  };

  const kase = await createCase({
    sourceType: "SOC_INVESTIGATION",
    title: input.title,
    summary: input.alertDetails ? input.alertDetails.slice(0, 2000) : `${events.length} events from ${parsed.map((p) => p.name).join(", ")}`,
    severity: "MEDIUM",
    status: "INVESTIGATING",
    metadata: metadata as unknown as Record<string, unknown>,
    actorId: input.actorId,
    tenantId: input.tenantId ?? null,
    deferPipelines: true,
  });

  const batchId = randomUUID();
  for (let i = 0; i < events.length; i += 1000) {
    await db.securityEvent.createMany({ data: events.slice(i, i + 1000).map((e) => toRow(e, kase.id, batchId)) });
  }

  await logAction({
    actorId: input.actorId,
    caseId: kase.id,
    action: "investigation.started",
    detail: { engine, eventCount: events.length, files: metadata.input.files, skipped },
  });

  return { caseId: kase.id, eventCount: events.length, skipped };
}

// --- pipeline --------------------------------------------------------------

async function readMeta(caseId: string): Promise<InvestigationMetadata> {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId }, select: { metadata: true } });
  return kase.metadata as unknown as InvestigationMetadata;
}

async function writeMeta(caseId: string, mutate: (m: InvestigationMetadata) => void) {
  const meta = await readMeta(caseId);
  mutate(meta);
  await db.case.update({ where: { id: caseId }, data: { metadata: JSON.parse(JSON.stringify(meta)) } });
  return meta;
}

async function stage<T>(
  caseId: string,
  name: StageName,
  provider: LlmProvider | null,
  model: (p: LlmProvider) => Promise<T>,
  fallback: () => T,
): Promise<T> {
  await writeMeta(caseId, (m) => {
    m.pipeline.status = "running";
    const s = m.pipeline.stages.find((x) => x.name === name)!;
    s.status = "running";
  });

  let result: T;
  let engine: PipelineStage["engine"] = "heuristic";
  let note: string | undefined;
  if (provider) {
    try {
      result = await model(provider);
      engine = provider.kind === "anthropic" ? "claude" : "local";
    } catch (err) {
      // A failed model call degrades this stage to the deterministic engine
      // instead of failing the whole investigation; the note says so.
      note = `${provider.name} call failed (${err instanceof Error ? err.message : String(err)}); used the deterministic engine.`;
      result = fallback();
    }
  } else {
    result = fallback();
  }

  await writeMeta(caseId, (m) => {
    const s = m.pipeline.stages.find((x) => x.name === name)!;
    s.status = "done";
    s.engine = engine;
    s.note = note;
    s.finishedAt = new Date().toISOString();
  });
  return result;
}

// Bound what gets persisted: the full graph can run to thousands of nodes.
// Keep everything within two hops of a flagged process.
export function focusGraph(graph: EntityGraph, findings: Finding[]): InvestigationMetadata["graph"] {
  if (graph.nodes.length <= MAX_STORED_GRAPH_NODES) return graph;
  const flagged = new Set<string>();
  for (const f of findings) {
    for (const e of f.events) {
      for (const n of graph.nodes) if (n.type === "process" && n.pid === e.processPid && n.host === (e.hostName ?? "unknown_host")) flagged.add(n.id);
    }
  }
  const keep = new Set(flagged);
  for (let hop = 0; hop < 2; hop++) {
    for (const e of graph.edges) {
      if (keep.has(e.source)) keep.add(e.target);
      if (keep.has(e.target)) keep.add(e.source);
    }
  }
  const nodes = graph.nodes.filter((n) => keep.has(n.id)).slice(0, MAX_STORED_GRAPH_NODES);
  const ids = new Set(nodes.map((n) => n.id));
  return { nodes, edges: graph.edges.filter((e) => ids.has(e.source) && ids.has(e.target)), truncated: true, totalNodes: graph.nodes.length };
}

const SEVERITY_FROM_TRIAGE: Record<TriageResult["severity"], CaseSeverity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

const SEVERITY_ORDER: CaseSeverity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

// Stamps each flagged event with the worst severity among the findings that
// cite it. The AI first responder's evidence window is capped, and reads
// these hints so a large upload shows it what the rules found rather than
// the log's first minutes.
async function markFlaggedEvents(rows: SecurityEvent[], events: UesEvent[], findings: Finding[]) {
  const rowId = new Map(events.map((e, i) => [e, rows[i].id]));
  const worst = new Map<string, CaseSeverity>();
  for (const f of findings) {
    for (const e of f.events) {
      const id = rowId.get(e);
      const prev = id && worst.get(id);
      if (id && (!prev || SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(prev))) worst.set(id, f.severity);
    }
  }
  const bySeverity = new Map<CaseSeverity, string[]>();
  for (const [id, severity] of worst) bySeverity.set(severity, [...(bySeverity.get(severity) ?? []), id]);
  for (const [severity, ids] of bySeverity) {
    for (let i = 0; i < ids.length; i += 5000) {
      await db.securityEvent.updateMany({ where: { id: { in: ids.slice(i, i + 5000) } }, data: { severityHint: severity.toLowerCase() } });
    }
  }
}

function indicatorsFrom(events: UesEvent[]): NewIndicator[] {
  const out: NewIndicator[] = [];
  for (const e of events) {
    if (e.dstIp && !isPrivateIp(e.dstIp)) out.push({ type: "IP", value: e.dstIp, role: "destination_ip" });
    // Where a logon came from, when that's on the internet.
    if (AUTH_TYPES.has(e.eventType) && e.hostIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(e.hostIp) && !isPrivateIp(e.hostIp)) out.push({ type: "IP", value: e.hostIp, role: "logon_source_ip" });
    if (e.fileHash && /^[a-f0-9]{64}$/.test(e.fileHash)) out.push({ type: "FILE_HASH", value: e.fileHash, role: "file_sha256" });
    if (e.query) out.push({ type: "DOMAIN", value: e.query.toLowerCase(), role: "dns_query" });
    if (e.commandLine) for (const ioc of extractIndicators(e.commandLine)) out.push({ ...ioc, role: "command_line" });
  }
  return out;
}

export async function runInvestigationPipeline(caseId: string) {
  const kase = await db.case.findUniqueOrThrow({ where: { id: caseId } });
  const meta = kase.metadata as unknown as InvestigationMetadata;
  const provider = meta.pipeline.engine === "heuristic" ? null : await resolveProvider("investigation");
  const useModel = !!provider;

  try {
    const rows = await db.securityEvent.findMany({ where: { caseId }, orderBy: { timestamp: "asc" } });
    const events = rows.map(fromRow);
    const graph = buildEntityGraph(events);
    const intel = await loadIntelSnapshot(events.map((e) => ({ type: "IP" as const, value: e.dstIp })));
    const findings = runForensicRules(events, intel);
    const flaggedEvents = [...new Set(findings.flatMap((f) => f.events))];
    await markFlaggedEvents(rows, events, findings);
    const prior: PriorCase[] = (
      await findRelatedCases(caseId, { limit: 5, extraIndicators: indicatorsFrom(flaggedEvents.length ? flaggedEvents : events) })
    ).map((c) => ({
      title: c.title,
      source: c.sourceType,
      verdict: c.verdict,
      severity: c.severity,
      openedAt: c.createdAt.toISOString(),
      sharedEvidence: c.reasons,
      rootCause: c.rootCauseNarrative?.slice(0, 400),
    }));
    const evidence = useModel ? buildEvidence(events, findings, graph) : "";

    const triage = await stage(caseId, "triage", provider, (p) => triageAgent(p, kase.title, meta.input.alertDetails, evidence), () => heuristicTriage(kase.title, findings));

    // RCA ⇄ QA loop: rebuild the RCA with the validator's objections until it
    // passes or three rounds have run. Mechanical checks (timestamps exist,
    // causality holds) are merged into whatever the QA agent reports.
    let rca: RcaResult | undefined;
    let qa: QaResult | undefined;
    let iterations = 0;
    while (iterations < MAX_QA_ITERATIONS) {
      iterations++;
      const feedback = qa?.issues;
      rca = await stage(caseId, "rca", provider, (p) => rcaAgent(p, triage, evidence, feedback, prior), () => heuristicRca(findings, graph, prior));
      const currentRca = rca;
      qa = await stage(caseId, "qa", provider, (p) => qaAgent(p, currentRca, evidence), () => heuristicQa(currentRca, events, graph));
      const mechanical = heuristicQa(currentRca, events, graph);
      const mergedIssues = [...new Set([...qa.issues, ...mechanical.issues])];
      qa = { ...qa, issues: mergedIssues, is_valid: qa.is_valid && mechanical.is_valid };
      await writeMeta(caseId, (m) => {
        m.pipeline.qaIterations = iterations;
      });
      if (qa.is_valid || !useModel) break; // the deterministic RCA wouldn't change on retry
    }

    const finalRca = rca!;
    const finalQa = qa!;
    const report = await stage(
      caseId,
      "report",
      provider,
      (p) => reportAgent(p, kase.title, triage, finalRca, finalQa),
      () => heuristicReport({ title: kase.title, triage, rca: finalRca, qa: finalQa, findings, events }),
    );

    const severity = SEVERITY_FROM_TRIAGE[triage.severity] ?? "MEDIUM";
    const verdict = findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL") || severity === "HIGH" || severity === "CRITICAL"
      ? "malicious"
      : findings.length || severity === "MEDIUM"
        ? "suspicious"
        : "benign";

    await writeMeta(caseId, (m) => {
      m.triage = triage;
      m.rca = finalRca;
      m.qa = finalQa;
      m.report = report;
      m.graph = focusGraph(graph, findings);
      m.findings = findings.map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, techniques: f.techniques, description: f.description, eventCount: f.events.length }));
      m.pipeline.status = "completed";
      m.pipeline.finishedAt = new Date().toISOString();
    });

    await db.case.update({
      where: { id: caseId },
      data: {
        severity,
        verdict,
        confidence: Math.max(0, Math.min(1, finalRca.confidence_score)),
        rootCauseNarrative: finalRca.root_cause,
        status: verdict === "benign" ? "TRIAGING" : "INVESTIGATING",
      },
    });

    const flagged = [...flaggedEvents].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    await appendToCase(caseId, {
      severity,
      detections: findings.map((f) => ({
        source: f.detectionSource,
        ruleId: `investigation:${f.ruleId}`,
        title: `${f.title} — ${f.description}`.slice(0, 240),
        severity: f.severity,
        fingerprint: createHash("sha256").update(`${caseId}|${f.ruleId}`).digest("hex"),
        evidence: { description: f.description, techniques: f.techniques, confidence: f.confidence, events: f.events.slice(0, 20).map(describeEvent) },
      })),
      timeline: flagged.slice(0, 200).map((e) => ({
        occurredAt: e.timestamp,
        actor: e.userName ?? e.hostName ?? null,
        action: `${e.platform}.${e.eventType}`,
        detail: describeEvent(e),
      })),
      techniques: [
        ...finalRca.mitre_techniques.map((t) => ({ id: t.id, confidence: finalRca.confidence_score })),
        ...findings.flatMap((f) => f.techniques.map((t) => ({ id: t, confidence: f.confidence }))),
      ],
      indicators: indicatorsFrom(flagged.length ? flagged : events),
    });

    await logAction({
      caseId,
      action: "investigation.completed",
      detail: { engine: meta.pipeline.engine, findings: findings.length, qaIterations: iterations, qaValid: finalQa.is_valid, verdict },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await writeMeta(caseId, (m) => {
      m.pipeline.status = "failed";
      m.pipeline.error = message;
      m.pipeline.finishedAt = new Date().toISOString();
      for (const s of m.pipeline.stages) if (s.status === "running") s.status = "failed";
    });
    await logAction({ caseId, action: "investigation.failed", detail: { error: message } });
  }
}

// Reset pipeline state for a re-run (after a failure or a stalled run).
export async function resetPipeline(caseId: string) {
  const { engine, engineName, model } = await pipelineEngine();
  await writeMeta(caseId, (m) => {
    m.pipeline = {
      status: "queued",
      engine,
      engineName,
      model,
      stages: (["triage", "rca", "qa", "report"] as StageName[]).map((name) => ({ name, status: "pending" })),
      qaIterations: 0,
      startedAt: new Date().toISOString(),
    };
  });
}
