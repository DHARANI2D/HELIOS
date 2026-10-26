import type { CaseSeverity, DetectionRule, DetectionRuleStatus, Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { fromEventRow } from "@/lib/siem/adapters";
import type { ScoredDetection } from "@/lib/siem/types";
import { compileSigma, splitRules, type CompiledSigma, type SigmaLevel } from "@/lib/detections/sigma";
import { logsourceFilter, sigmaEvent, type EventRow } from "@/lib/detections/sigma-fields";
import { applyTuning, validRegex, type Tuning, type TuningField, type TuningKind, type TuningOp } from "@/lib/detections/tuning";

// Sigma rules and tuning on the server. Imported rules start in testing:
// they run on every batch and count what they match (with samples) but open
// nothing until a detection engineer makes them active. Active rules raise
// detections like the built-in detectors, through the same correlation,
// allowlist and case flow; tuning then applies per client to both.

const LEVEL_RISK: Record<SigmaLevel, { risk: number; confidence: number }> = {
  critical: { risk: 900, confidence: 0.95 },
  high: { risk: 600, confidence: 0.85 },
  medium: { risk: 300, confidence: 0.65 },
  low: { risk: 120, confidence: 0.45 },
  informational: { risk: 40, confidence: 0.25 },
};

// ---------------------------------------------------------------- import

export interface RuleCheck {
  index: number;
  ok: boolean;
  title: string;
  sigmaId?: string;
  level?: string;
  techniques?: string[];
  errors: string[];
  warnings: string[];
  backtest?: { events: number; matched: number; samples: string[]; days: number };
}

function warningsFor(rule: CompiledSigma): string[] {
  const out: string[] = [];
  const ls = [rule.logsource.product, rule.logsource.category, rule.logsource.service].filter(Boolean).join("/");
  if (!logsourceFilter(rule.logsource).known) out.push(`The log source ${ls || "(none)"} isn't mapped: the rule is checked against every event`);
  if (rule.level === "informational") out.push("Informational rules are for hunting: they count matches but never open cases");
  return out;
}

const describe = (r: EventRow) => [r.timestamp.toISOString().slice(0, 19).replace("T", " "), r.eventType, r.hostName && `host=${r.hostName}`, r.userName && `user=${r.userName}`, r.processName && `proc=${r.processName}`, r.commandLine && `cmd=${r.commandLine.slice(0, 160)}`, r.destIp && `dst=${r.destIp}`].filter(Boolean).join(" ");

const ROW_SELECT = { id: true, timestamp: true, source: true, platform: true, eventType: true, classUid: true, userName: true, hostName: true, service: true, processName: true, processPid: true, parentProcessName: true, parentProcessPid: true, commandLine: true, sourceIp: true, destIp: true, destPort: true, filePath: true, fileHash: true, metadata: true, ocsf: true, geo: true, severityHint: true } as const;

// The rule run over a client's recent events (or everyone's, for a rule
// meant for every client), capped so a broad rule can't stall the page.
export async function backtest(rule: CompiledSigma, tenantId: string | null | undefined, days = 7, cap = 20_000) {
  const since = new Date(Date.now() - days * 86_400_000);
  const rows = await db.securityEvent.findMany({ where: { ...(tenantId !== undefined ? { tenantId } : {}), timestamp: { gte: since } }, orderBy: { timestamp: "desc" }, take: cap, select: ROW_SELECT });
  const ls = logsourceFilter(rule.logsource);
  const matched = rows.filter((r) => ls.test(r) && rule.match(sigmaEvent(r)));
  return { events: rows.length, matched: matched.length, samples: matched.slice(0, 5).map(describe), days };
}

export async function checkRules(text: string, tenantId?: string | null): Promise<RuleCheck[]> {
  const docs = splitRules(text);
  if (!docs.length) throw new Error("Paste at least one Sigma rule");
  if (docs.length > 50) throw new Error("At most 50 rules at a time");
  const out: RuleCheck[] = [];
  for (const [index, doc] of docs.entries()) {
    const c = compileSigma(doc);
    if (!c.ok) {
      out.push({ index, ok: false, title: doc.match(/^title:\s*(.+)$/m)?.[1]?.trim() ?? `Rule ${index + 1}`, errors: c.errors, warnings: [] });
      continue;
    }
    out.push({ index, ok: true, title: c.rule.title, sigmaId: c.rule.sigmaId, level: c.rule.level, techniques: c.rule.techniques, errors: [], warnings: warningsFor(c.rule), backtest: await backtest(c.rule, tenantId ?? undefined) });
  }
  return out;
}

export async function importRules(text: string, opts: { tenantId: string | null; actorId: string }) {
  const results: Array<{ title: string; ok: boolean; errors: string[]; id?: string; updated?: boolean }> = [];
  for (const doc of splitRules(text)) {
    const c = compileSigma(doc);
    if (!c.ok) {
      results.push({ title: doc.match(/^title:\s*(.+)$/m)?.[1]?.trim() ?? "Untitled rule", ok: false, errors: c.errors });
      continue;
    }
    const r = c.rule;
    const data = {
      title: r.title.slice(0, 300),
      description: r.description.slice(0, 4000) || null,
      level: r.level,
      yaml: doc,
      techniques: r.techniques,
      tactics: r.tactics,
      logsource: [r.logsource.product, r.logsource.category, r.logsource.service].filter(Boolean).join("/") || "any",
      warnings: warningsFor(r),
      updatedById: opts.actorId,
    };
    const existing = await db.detectionRule.findFirst({ where: { sigmaId: r.sigmaId, tenantId: opts.tenantId } });
    // A changed rule goes back to testing: its matches need checking again.
    const saved = existing
      ? await db.detectionRule.update({ where: { id: existing.id }, data: { ...data, status: existing.yaml === doc ? existing.status : "TESTING", ...(existing.yaml === doc ? {} : { testHits: 0, samples: [] as Prisma.InputJsonValue, lastHitAt: null }) } })
      : await db.detectionRule.create({ data: { ...data, sigmaId: r.sigmaId, tenantId: opts.tenantId, status: "TESTING", createdById: opts.actorId } });
    results.push({ title: r.title, ok: true, errors: [], id: saved.id, updated: !!existing });
  }
  await logAction({ actorId: opts.actorId, action: "detections.rules_imported", detail: { tenantId: opts.tenantId, imported: results.filter((r) => r.ok).length, refused: results.filter((r) => !r.ok).map((r) => r.title) } });
  forgetRules();
  return results;
}

export async function setRuleStatus(id: string, status: DetectionRuleStatus, actorId: string) {
  const rule = await db.detectionRule.findUniqueOrThrow({ where: { id } });
  if (status === "ACTIVE" && rule.level === "informational") throw new Error("Informational rules are for hunting and stay in testing");
  if (status === "ACTIVE" && !compileSigma(rule.yaml).ok) throw new Error("This rule no longer compiles");
  await db.detectionRule.update({ where: { id }, data: { status, updatedById: actorId } });
  await logAction({ actorId, action: "detections.rule_status", detail: { ruleId: id, sigmaId: rule.sigmaId, from: rule.status, to: status, testHits: rule.testHits } });
  forgetRules();
}

export async function deleteRule(id: string, actorId: string) {
  const rule = await db.detectionRule.delete({ where: { id } });
  await logAction({ actorId, action: "detections.rule_deleted", detail: { ruleId: id, sigmaId: rule.sigmaId, title: rule.title } });
  forgetRules();
}

// ---------------------------------------------------------------- tuning

export interface TuningInput {
  tenantId: string;
  target: string;
  kind: TuningKind;
  field?: TuningField | null;
  op?: TuningOp | null;
  value?: string | null;
  severity?: CaseSeverity | null;
  reason: string;
  expiresAt?: Date | null;
}

export async function addTuning(input: TuningInput, actorId: string) {
  if (!input.reason.trim()) throw new Error("Say why: tuning without a reason can't be reviewed");
  if (input.kind === "exclude" && (!input.field || !input.op || !input.value?.trim())) throw new Error("An exclusion needs a field, a test and a value");
  if (input.op === "regex" && input.value && !validRegex(input.value)) throw new Error("That isn't a valid regular expression");
  if (input.kind === "severity" && !input.severity) throw new Error("Pick the severity");
  if (input.expiresAt && input.expiresAt <= new Date()) throw new Error("The expiry has to be in the future");
  const row = await db.detectionTuning.create({
    data: {
      tenantId: input.tenantId,
      target: input.target,
      kind: input.kind,
      field: input.kind === "exclude" ? input.field : null,
      op: input.kind === "exclude" ? input.op : null,
      value: input.kind === "exclude" ? input.value!.trim() : null,
      severity: input.kind === "severity" ? input.severity : null,
      reason: input.reason.trim(),
      expiresAt: input.expiresAt ?? null,
      createdById: actorId,
    },
  });
  await logAction({ actorId, action: "detections.tuning_added", detail: { tuningId: row.id, tenantId: row.tenantId, target: row.target, kind: row.kind, field: row.field, op: row.op, value: row.value, severity: row.severity, reason: row.reason, expiresAt: row.expiresAt } });
  return row;
}

export async function removeTuning(id: string, actorId: string) {
  const row = await db.detectionTuning.delete({ where: { id } });
  await logAction({ actorId, action: "detections.tuning_removed", detail: { tuningId: id, tenantId: row.tenantId, target: row.target, kind: row.kind, hits: row.hits } });
}

// ---------------------------------------------------------------- at ingest

interface LoadedRule {
  row: Pick<DetectionRule, "id" | "sigmaId" | "status" | "tenantId" | "updatedAt">;
  compiled: CompiledSigma;
  filter: ReturnType<typeof logsourceFilter>;
}

const TTL_MS = 30_000;
let cache: { at: number; rules: LoadedRule[] } | null = null;
export const forgetRules = () => {
  cache = null;
};

async function loadRules(): Promise<LoadedRule[]> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache.rules;
  const rows = await db.detectionRule.findMany({ where: { status: { in: ["ACTIVE", "TESTING"] } }, select: { id: true, sigmaId: true, status: true, tenantId: true, updatedAt: true, yaml: true } });
  const rules = rows.flatMap((row) => {
    const c = compileSigma(row.yaml);
    return c.ok ? [{ row, compiled: c.rule, filter: logsourceFilter(c.rule.logsource) }] : [];
  });
  cache = { at: Date.now(), rules };
  return rules;
}

// Runs the rules on one batch's events: active ones become detections,
// testing ones are only counted.
export async function sigmaDetections(batchId: string, tenantId: string | null): Promise<ScoredDetection[]> {
  const rules = (await loadRules()).filter((r) => r.row.tenantId === null || r.row.tenantId === tenantId);
  if (!rules.length) return [];
  const rows = await db.securityEvent.findMany({ where: { batchId }, select: ROW_SELECT });
  if (!rows.length) return [];
  const out: ScoredDetection[] = [];
  for (const rule of rules) {
    const matched = rows.filter((r) => rule.filter.test(r) && rule.compiled.match(sigmaEvent(r)));
    if (!matched.length) continue;
    if (rule.row.status === "TESTING" || rule.compiled.level === "informational") {
      const current = await db.detectionRule.findUnique({ where: { id: rule.row.id }, select: { samples: true } });
      const samples = [...matched.slice(0, 5).map(describe), ...(((current?.samples as string[] | null) ?? []))].slice(0, 5);
      await db.detectionRule.update({ where: { id: rule.row.id }, data: { testHits: { increment: matched.length }, lastHitAt: new Date(), samples } });
      continue;
    }
    await db.detectionRule.update({ where: { id: rule.row.id }, data: { lastHitAt: new Date() } });
    // One detection per rule and risk object, as the built-in detectors do.
    const groups = new Map<string, typeof matched>();
    for (const r of matched) {
      const key = r.userName ?? r.hostName ?? r.sourceIp ?? "unknown";
      groups.set(key, [...(groups.get(key) ?? []), r]);
    }
    const { risk, confidence } = LEVEL_RISK[rule.compiled.level];
    for (const group of groups.values()) {
      const events = group.slice(0, 20).map(fromEventRow);
      const first = group[0];
      const riskObjectType = first.userName ? "user" : first.hostName ? "host" : first.sourceIp ? "ip" : "unknown";
      out.push({
        detector: "sigma",
        detectionSource: "SIGMA_RULE",
        ruleId: rule.compiled.sigmaId,
        matchedEvents: events,
        signals: ["sigma", rule.compiled.level, ...rule.compiled.techniques],
        confidence,
        reasoning: [`Sigma rule "${rule.compiled.title}" (${rule.compiled.level}) matched ${group.length} event${group.length === 1 ? "" : "s"}`, ...(rule.compiled.description ? [rule.compiled.description.slice(0, 300)] : [])],
        mitreTactics: rule.compiled.tactics,
        mitreTechniques: rule.compiled.techniques,
        riskScore: risk,
        riskObject: first.userName ?? first.hostName ?? first.sourceIp ?? "unknown",
        riskObjectType,
      });
    }
  }
  return out;
}

export async function tuneDetections(detections: ScoredDetection[], tenantId: string | null, now = new Date()) {
  if (!tenantId || !detections.length) return { detections, suppressed: 0 };
  const rows = await db.detectionTuning.findMany({ where: { tenantId, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] } });
  if (!rows.length) return { detections, suppressed: 0 };
  const result = applyTuning(detections, rows as Tuning[], now);
  for (const [id, n] of result.hits) await db.detectionTuning.update({ where: { id }, data: { hits: { increment: n }, lastHitAt: now } });
  return { detections: result.detections, suppressed: result.suppressed };
}
