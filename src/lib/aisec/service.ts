import { randomBytes } from "node:crypto";
import type { AiSystem, CaseSeverity, Prisma, UserRole } from "@prisma/client";

import { db } from "@/lib/db";
import { logAction } from "@/lib/audit";
import { sealFor } from "@/lib/keys";
import { hashToken, newToken } from "@/lib/secrets";
import { rowFromColumns } from "@/lib/ocsf/rows";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { appendToCase, createCase, type NewDetection } from "@/lib/cases/writer";
import { maxSeverity } from "@/lib/severity";
import { evaluateGuard, type GuardRequest, type GuardResult } from "@/lib/aisec/guard";
import { PACKS, applyPack, policySchema, readPolicy, recommendationsFor, starterPolicy } from "@/lib/aisec/policy";
import { contentHash, issueReceipt, type Receipt } from "@/lib/aisec/receipts";
import { safeExcerpt } from "@/lib/aisec/detectors";

// AI systems on the server: registering a client's AI application, its
// key, its guard policy and the versions of it, and every guard decision
// kept as a security event on the client (so Explore, detections, reports
// and retention treat AI traffic like any other log). Leaks, poisoned
// content, agents steered off their task and sustained attacks open a case
// for the SOC; one open case per system collects them.

export const KINDS = { CHATBOT: "Chat assistant", AGENT: "Agent with tools", RAG: "Search / RAG application", MODEL_API: "Model API" } as const;
export type SystemKind = keyof typeof KINDS;
export const DATA_CLASSES = { pii: "Personal data", phi: "Health records", pci: "Payment card data", secrets: "Credentials and keys", source_code: "Source code", internal: "Internal documents" } as const;

export class AiSecError extends Error {}

export interface AiActor {
  id: string;
  name: string;
  role: UserRole;
  isClient: boolean;
  tenantId: string | null;
}

const json = (v: unknown) => JSON.parse(JSON.stringify(v)) as Prisma.InputJsonValue;
const KEY_PREFIX = "hgs";

function assertSameClient(actor: AiActor, tenantId: string) {
  if (actor.isClient && actor.tenantId !== tenantId) throw new AiSecError("Not found");
}

async function systemFor(actor: AiActor, systemId: string) {
  const s = await db.aiSystem.findUnique({ where: { id: systemId } });
  if (!s) throw new AiSecError("Not found");
  assertSameClient(actor, s.tenantId);
  return s;
}

export const policyOf = (s: Pick<AiSystem, "policy">) => readPolicy(s.policy);
export const modeOf = (s: Pick<AiSystem, "mode">) => (s.mode === "monitor" ? "monitor" : "enforce") as "enforce" | "monitor";

// ---------------------------------------------------------------- endpoints

// What the red team (and the profile) accepts as an endpoint: https only,
// and a host the security test will have to verify anyway.
export function checkEndpoint(raw: string | null | undefined): string | null {
  const v = raw?.trim();
  if (!v) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new AiSecError("The endpoint isn't a URL");
  }
  if (u.protocol !== "https:") throw new AiSecError("The endpoint must be https://");
  return u.toString();
}

function checkUpstream(raw: string | null | undefined): string | null {
  const v = raw?.trim().replace(/\/+$/, "");
  if (!v) return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new AiSecError("The model provider address isn't a URL");
  }
  if (u.protocol !== "https:" && process.env.HELIOS_AI_GATEWAY_ALLOW_PRIVATE !== "1") throw new AiSecError("The model provider address must be https:// (a local model needs HELIOS_AI_GATEWAY_ALLOW_PRIVATE=1 on the server)");
  return v;
}

// ---------------------------------------------------------------- systems

export interface SystemInput {
  tenantId: string;
  name: string;
  kind: SystemKind;
  description?: string | null;
  owner?: string | null;
  dataClasses: string[];
  endpoint?: string | null;
}

export async function registerSystem(input: SystemInput, actor: AiActor) {
  assertSameClient(actor, input.tenantId);
  const name = input.name.trim();
  if (!name) throw new AiSecError("Name the AI system");
  if (!(input.kind in KINDS)) throw new AiSecError("Pick what kind of AI system it is");
  if (await db.aiSystem.findFirst({ where: { tenantId: input.tenantId, name } })) throw new AiSecError(`${name} is already registered`);
  const dataClasses = input.dataClasses.filter((d) => d in DATA_CLASSES);
  const policy = starterPolicy(dataClasses, input.kind);
  const system = await db.aiSystem.create({
    data: {
      tenantId: input.tenantId,
      name: name.slice(0, 120),
      kind: input.kind,
      description: input.description?.trim().slice(0, 2000) || null,
      owner: input.owner?.trim().slice(0, 200) || null,
      dataClasses,
      endpoint: checkEndpoint(input.endpoint),
      policy: json(policy),
      canary: `helios-canary-${randomBytes(6).toString("hex")}`,
      createdByName: actor.name,
      versions: { create: { tenantId: input.tenantId, version: 1, policy: json(policy), mode: "enforce", reason: `Registered: baseline${policy.packs.length > 1 ? ` with ${policy.packs.slice(1).map((p) => PACKS[p]?.label ?? p).join(", ")}` : ""}`, byName: actor.name } },
    },
  });
  await logAction({ actorId: actor.id, action: "aisec.system_registered", detail: { systemId: system.id, tenantId: input.tenantId, name, kind: input.kind, dataClasses, packs: policy.packs } });
  return system;
}

export interface ProfileInput {
  name?: string;
  description?: string | null;
  owner?: string | null;
  dataClasses?: string[];
  status?: "active" | "paused" | "retired";
  endpoint?: string | null;
  endpointFormat?: "openai" | "json";
  endpointModel?: string | null;
  requestTemplate?: string | null;
  responsePath?: string | null;
  authHeader?: string | null;
  // undefined: keep; "": remove; otherwise the new value (sealed).
  authValue?: string;
  upstreamUrl?: string | null;
  upstreamModel?: string | null;
  upstreamKey?: string;
  privacyMode?: boolean;
  retainContent?: boolean;
}

export async function updateProfile(systemId: string, input: ProfileInput, actor: AiActor) {
  const s = await systemFor(actor, systemId);
  const data: Prisma.AiSystemUpdateInput = {};
  if (input.name !== undefined) {
    const name = input.name.trim();
    if (!name) throw new AiSecError("Name the AI system");
    if (name !== s.name && (await db.aiSystem.findFirst({ where: { tenantId: s.tenantId, name } }))) throw new AiSecError(`${name} is already registered`);
    data.name = name.slice(0, 120);
  }
  if (input.description !== undefined) data.description = input.description?.trim().slice(0, 2000) || null;
  if (input.owner !== undefined) data.owner = input.owner?.trim().slice(0, 200) || null;
  if (input.dataClasses) data.dataClasses = input.dataClasses.filter((d) => d in DATA_CLASSES);
  if (input.status) data.status = input.status;
  if (input.endpoint !== undefined) data.endpoint = checkEndpoint(input.endpoint);
  if (input.endpointFormat) data.endpointFormat = input.endpointFormat;
  if (input.endpointModel !== undefined) data.endpointModel = input.endpointModel?.trim().slice(0, 120) || null;
  if (input.requestTemplate !== undefined) {
    const t = input.requestTemplate?.trim() || null;
    if (t) {
      if (!t.includes("{{prompt}}")) throw new AiSecError("The request body must contain {{prompt}} where the message goes");
      try {
        JSON.parse(t.replace(/\{\{prompt\}\}/g, "x"));
      } catch {
        throw new AiSecError("The request body must be JSON (with {{prompt}} inside a string)");
      }
    }
    data.requestTemplate = t;
  }
  if (input.responsePath !== undefined) data.responsePath = input.responsePath?.trim().slice(0, 200) || null;
  if (input.authHeader !== undefined) {
    const h = input.authHeader?.trim() || null;
    if (h && !/^[A-Za-z0-9-]{1,60}$/.test(h)) throw new AiSecError("The header name can only have letters, digits and dashes");
    data.authHeader = h;
  }
  if (input.authValue !== undefined) data.authCipher = input.authValue ? await sealFor(s.tenantId, input.authValue) : null;
  if (input.upstreamUrl !== undefined) data.upstreamUrl = checkUpstream(input.upstreamUrl);
  if (input.upstreamModel !== undefined) data.upstreamModel = input.upstreamModel?.trim().slice(0, 120) || null;
  if (input.upstreamKey !== undefined) data.upstreamCipher = input.upstreamKey ? await sealFor(s.tenantId, input.upstreamKey) : null;
  if (input.privacyMode !== undefined) data.privacyMode = input.privacyMode;
  if (input.retainContent !== undefined) data.retainContent = input.retainContent;
  const updated = await db.aiSystem.update({ where: { id: systemId }, data });
  const changed = Object.keys(data).map((k) => (k === "authCipher" ? "endpoint credential" : k === "upstreamCipher" ? "provider key" : k));
  await logAction({ actorId: actor.id, action: "aisec.profile_updated", detail: { systemId, name: updated.name, changed } });
  return updated;
}

// A new version of the policy, in force on the next call.
export async function savePolicy(systemId: string, raw: unknown, mode: "enforce" | "monitor", reason: string, actor: AiActor) {
  const s = await systemFor(actor, systemId);
  const parsed = policySchema.safeParse(raw);
  if (!parsed.success) throw new AiSecError(`The policy isn't valid: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  for (const r of parsed.data.tools.rules) {
    for (const a of r.args) {
      if (a.test === "matches" || a.test === "not_matches") {
        try {
          new RegExp(a.value, "i");
        } catch {
          throw new AiSecError(`The pattern for ${r.name}.${a.arg} isn't a valid regular expression`);
        }
      }
      if (a.test === "max" && !Number.isFinite(Number(a.value))) throw new AiSecError(`The limit for ${r.name}.${a.arg} must be a number`);
    }
  }
  if (!reason.trim()) throw new AiSecError("Say what changed and why");
  const version = s.policyVersion + 1;
  await db.$transaction([
    db.aiSystem.update({ where: { id: systemId }, data: { policy: json(parsed.data), policyVersion: version, mode } }),
    db.aiPolicyVersion.create({ data: { systemId, tenantId: s.tenantId, version, policy: json(parsed.data), mode, reason: reason.trim().slice(0, 1000), byName: actor.name } }),
  ]);
  await logAction({ actorId: actor.id, action: "aisec.policy_saved", detail: { systemId, name: s.name, version, mode, reason: reason.trim(), modeChanged: mode !== s.mode } });
  return { version };
}

export async function applyPackToSystem(systemId: string, pack: string, actor: AiActor) {
  const s = await systemFor(actor, systemId);
  if (!PACKS[pack]) throw new AiSecError("Unknown pack");
  return savePolicy(systemId, applyPack(policyOf(s), pack), modeOf(s), `Applied the ${PACKS[pack].label} pack`, actor);
}

// Turns the red team's findings into policy: the protections it recommends.
export async function applyRecommendations(systemId: string, ids: string[], actor: AiActor) {
  const s = await systemFor(actor, systemId);
  const open = openOwasp(s);
  const recs = recommendationsFor(open, policyOf(s)).filter((r) => ids.includes(r.id));
  if (!recs.length) throw new AiSecError("Nothing to apply: the policy already has these protections");
  const next = recs.reduce((p, r) => r.apply(p), policyOf(s));
  return savePolicy(systemId, next, "enforce", `From the red team: ${recs.map((r) => r.title.toLowerCase()).join("; ")}`, actor);
}

// The key the application uses for the guard and the gateway; shown once.
export async function issueKey(systemId: string, actor: AiActor) {
  const s = await systemFor(actor, systemId);
  const { token, hash, display } = newToken(KEY_PREFIX);
  await db.aiSystem.update({ where: { id: systemId }, data: { keyHash: hash, keyPrefix: display } });
  await logAction({ actorId: actor.id, action: s.keyHash ? "aisec.key_rotated" : "aisec.key_issued", detail: { systemId, name: s.name, prefix: display } });
  return { token, prefix: display };
}

export async function revokeKey(systemId: string, actor: AiActor) {
  const s = await systemFor(actor, systemId);
  await db.aiSystem.update({ where: { id: systemId }, data: { keyHash: null, keyPrefix: null } });
  await logAction({ actorId: actor.id, action: "aisec.key_revoked", detail: { systemId, name: s.name } });
}

export async function systemForKey(authorization: string | null) {
  const token = authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token?.startsWith(`${KEY_PREFIX}_`)) return null;
  const s = await db.aiSystem.findUnique({ where: { keyHash: hashToken(token) }, include: { tenant: { select: { status: true, name: true } } } });
  if (!s || s.status === "retired" || s.tenant.status === "SUSPENDED") return null;
  return s;
}

// The OWASP categories with open red-team findings on this system.
export function openOwasp(s: Pick<AiSystem, "redTeam">): string[] {
  const rt = (s.redTeam ?? null) as { categories?: Record<string, { open?: number }> } | null;
  return Object.entries(rt?.categories ?? {}).filter(([, v]) => (v.open ?? 0) > 0).map(([k]) => k);
}

// ---------------------------------------------------------------- the guard at runtime

const windows = new Map<string, { start: number; count: number; logged: boolean }>();

function overLimit(systemId: string, perMinute: number, now: number) {
  const w = windows.get(systemId);
  if (!w || now - w.start > 60_000) {
    windows.set(systemId, { start: now, count: 1, logged: false });
    return { over: false, first: false };
  }
  w.count++;
  if (w.count <= perMinute) return { over: false, first: false };
  const first = !w.logged;
  w.logged = true;
  return { over: true, first };
}

export interface GuardCall extends GuardRequest {
  user?: { id?: string; roles?: string[]; ip?: string };
  session?: string;
}

export interface GuardOutcome extends GuardResult {
  receipt: Receipt;
  caseId: string | null;
}

const SEVERITY_HINT = { allow: "info", watch: "low", redact: "low", block: "medium" } as const;

export async function guard(system: AiSystem, call: GuardCall, now = new Date()): Promise<GuardOutcome> {
  const policy = policyOf(system);
  const mode = modeOf(system);
  const limit = overLimit(system.id, policy.limits.requestsPerMinute, now.getTime());
  let result: GuardResult;
  if (limit.over) {
    const message = `Over this system's limit of ${policy.limits.requestsPerMinute} requests a minute`;
    result = { decision: "block", enforced: mode === "monitor" ? "watch" : "block", findings: [{ rule: "limit.rate", verdict: "block", message, owasp: ["LLM10"], atlas: ["AML.T0029"] }], explanation: `${mode === "monitor" ? "Monitor mode: would have been blocked" : "Blocked"}. ${message} (OWASP LLM10).` };
  } else {
    result = evaluateGuard({ policy, mode, canary: system.canary }, call);
  }
  const text = call.content ?? (call.tool ? JSON.stringify(call.tool) : call.documents ? call.documents.map((d) => d.text).join("\n") : "");
  const receipt = issueReceipt({ system: system.id, stage: call.stage, decision: result.decision, enforced: result.enforced, rules: result.findings.map((f) => f.rule), contentSha256: contentHash(text), policyVersion: system.policyVersion }, now);
  // A rate-limited flood is recorded once per minute, not per request.
  const record = !limit.over || limit.first;
  const caseId = record ? await recordDecision(system, call, result, receipt, text, now) : null;
  if (!system.lastSeenAt || now.getTime() - system.lastSeenAt.getTime() > 60_000) await db.aiSystem.update({ where: { id: system.id }, data: { lastSeenAt: now } }).catch(() => undefined);
  return { ...result, receipt, caseId };
}

export const hideCanary = (text: string, canary: string) => (canary ? text.replace(new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "[CANARY]") : text);

const subjectOf = (call: GuardCall) => call.user?.id?.slice(0, 120) || call.user?.ip?.slice(0, 64) || call.session?.slice(0, 120) || null;

async function recordDecision(system: AiSystem, call: GuardCall, result: GuardResult, receipt: Receipt, text: string, now: Date): Promise<string | null> {
  const subject = subjectOf(call);
  const owasp = [...new Set(result.findings.flatMap((f) => f.owasp))];
  const atlas = [...new Set(result.findings.flatMap((f) => f.atlas))];
  const sealed = system.retainContent && text ? await sealFor(system.tenantId, JSON.stringify({ stage: call.stage, content: call.content ?? null, tool: call.tool ?? null, documents: call.documents?.map((d) => ({ id: d.id, text: d.text })) ?? null })) : null;
  const event = await db.securityEvent.create({
    data: rowFromColumns(
      {
        timestamp: now,
        source: "cloud",
        platform: "helios-ai-guard",
        eventType: `ai.guard.${result.decision}`,
        userName: subject,
        sourceIp: call.user?.ip && /^[0-9a-f.:]{3,45}$/i.test(call.user.ip) ? call.user.ip : null,
        service: system.name,
        severityHint: SEVERITY_HINT[result.decision],
        metadata: JSON.parse(JSON.stringify({
          systemId: system.id,
          stage: call.stage,
          decision: result.decision,
          enforced: result.enforced,
          mode: modeOf(system),
          rules: result.findings.map((f) => f.rule),
          findings: result.findings.slice(0, 10).map((f) => ({ rule: f.rule, verdict: f.verdict, message: f.message, owasp: f.owasp })),
          owasp,
          atlas,
          tool: call.tool?.name ?? null,
          task: call.task ?? null,
          // The canary never goes into a log: it would hand it to anyone reading events.
          excerpt: text ? safeExcerpt(hideCanary(text, system.canary), 160) : null,
          receipt: receipt.body.id,
          signature: receipt.signature,
          keyId: receipt.keyId,
          policyVersion: system.policyVersion,
          ...(sealed ? { sealedContent: sealed } : {}),
        })),
      },
      { tenantId: system.tenantId },
    ),
  });
  if (result.decision === "allow") return null;
  return openCaseIfNeeded(system, call, result, event.id, subject, now);
}

interface Signal {
  rule: string;
  title: string;
  severity: CaseSeverity;
}

async function signalsOf(system: AiSystem, call: GuardCall, result: GuardResult, subject: string | null, now: Date): Promise<Signal[]> {
  const rules = new Set(result.findings.map((f) => f.rule));
  const out: Signal[] = [];
  if (rules.has("canary")) out.push({ rule: "canary", title: "System prompt leaked in an answer", severity: "HIGH" });
  if (call.stage === "output" && rules.has("secret")) out.push({ rule: "secret", title: "Credential in an answer", severity: "HIGH" });
  if (rules.has("output.exfiltration")) out.push({ rule: "output.exfiltration", title: "Answer tried to send the conversation to an outside address", severity: "HIGH" });
  if ((call.stage === "retrieval" || call.stage === "tool_output") && [...rules].some((r) => r.startsWith("injection."))) out.push({ rule: "indirect_injection", title: `Instructions planted in ${call.stage === "retrieval" ? "documents" : "tool results"} the AI reads`, severity: "HIGH" });
  if (rules.has("tool.task_scope")) out.push({ rule: "tool.task_scope", title: "Agent steered off its task", severity: "MEDIUM" });
  if (rules.has("tool.argument") || rules.has("tool.blocked")) out.push({ rule: "tool.blocked", title: "Agent tried a tool action its policy forbids", severity: "MEDIUM" });
  const attack = call.stage === "prompt" && [...rules].some((r) => r.startsWith("injection.") || r === "jailbreak" || r === "prompt_extraction");
  if (attack && subject) {
    const since = new Date(now.getTime() - 10 * 60_000);
    const recent = await db.securityEvent.count({ where: { tenantId: system.tenantId, platform: "helios-ai-guard", service: system.name, userName: subject, eventType: { in: ["ai.guard.block", "ai.guard.watch"] }, timestamp: { gte: since, lte: now } } });
    if (recent >= 5) out.push({ rule: "sustained_attack", title: `Repeated prompt injection from ${subject}`, severity: "MEDIUM" });
  }
  return out;
}

async function openCaseIfNeeded(system: AiSystem, call: GuardCall, result: GuardResult, eventId: string, subject: string | null, now: Date): Promise<string | null> {
  const all = await signalsOf(system, call, result, subject, now);
  if (!all.length) return null;
  // One detection per signal, per subject, per hour: a flood files one, not thousands.
  const fingerprint = (s: Signal) => `ai-guard:${system.id}:${s.rule}:${subject ?? "-"}:${now.toISOString().slice(0, 13)}`;
  const known = new Set((await db.detection.findMany({ where: { fingerprint: { in: all.map(fingerprint) } }, select: { fingerprint: true } })).map((d) => d.fingerprint));
  const signals = all.filter((s) => !known.has(fingerprint(s)));
  const ref = `ai-system:${system.id}`;
  const open = await db.case.findFirst({ where: { sourceType: "SIEM_ALERT", sourceRef: ref, status: { notIn: CLOSED_STATUSES } }, orderBy: { createdAt: "desc" }, select: { id: true } });
  if (!signals.length) {
    // Already reported this hour: link the event to the case, nothing more.
    if (open) await db.securityEvent.updateMany({ where: { id: eventId }, data: { caseId: open.id } });
    return open?.id ?? null;
  }
  const severity = maxSeverity(...signals.map((s) => s.severity));
  const detections: NewDetection[] = signals.map((s) => ({
    source: "AI_GUARD",
    ruleId: `ai-guard:${s.rule}`,
    title: `${system.name}: ${s.title}`,
    severity: s.severity,
    evidence: { systemId: system.id, stage: call.stage, decision: result.decision, findings: result.findings.slice(0, 8), subject, tool: call.tool?.name ?? null },
    fingerprint: fingerprint(s),
  }));
  const timeline = signals.map((s) => ({ occurredAt: now, actor: subject ?? "unknown user", action: `ai.${call.stage}`, detail: `${s.title}: ${result.explanation}` }));
  if (open) {
    await appendToCase(open.id, { severity, detections, timeline, eventIds: [eventId] });
    return open.id;
  }
  const kase = await createCase({
    sourceType: "SIEM_ALERT",
    sourceRef: ref,
    domain: "AI_AGENTS",
    tenantId: system.tenantId,
    title: `AI system ${system.name}: ${signals[0].title.charAt(0).toLowerCase()}${signals[0].title.slice(1)}`,
    summary: `${result.explanation} Seen by the HELIOS AI guard on ${system.name}${modeOf(system) === "monitor" ? " (monitor mode: recorded, not blocked)" : ""}.`,
    severity,
    metadata: { aiSystemId: system.id, aiSystem: system.name, owasp: [...new Set(result.findings.flatMap((f) => f.owasp))] },
    detections,
    timeline,
    eventIds: [eventId],
  });
  return kase.id;
}
