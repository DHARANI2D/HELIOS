import type { Prisma } from "@prisma/client";
import { z } from "zod";

import { db } from "@/lib/db";
import { findRelatedCases } from "@/lib/cases/related";
import { getTactic, getTechnique } from "@/lib/mitre/catalog";
import { parseProtections } from "@/lib/endpoints/controls";
import { escapeUntrusted, scanText, type InjectionFinding } from "@/lib/ai/safety";
import type { CaseEntities, EvidenceRef } from "@/lib/ai/evidence";
import type { LlmProvider } from "@/lib/ai/provider";
import { extractFacts, renderFacts } from "@/lib/ai/investigator/extract";

// The investigation agent's tools. Every one only reads, and only this
// client's data (the case's tenant; internal cases see internal data): no
// tool can write, call out to the internet or reach another client. Results
// come back as evidence lines with ids (Q1, Q2…) the agent must cite, and
// what they name (hosts, accounts, IPs, hashes) joins the entities its
// containment may target. Short fields written on the client's systems
// (command lines, paths, titles) are escaped and scanned for text aimed at
// the AI, and withheld if they carry any; long free text only ever reaches
// the agent through the extractor (lib/ai/investigator/extract.ts).

export interface InvestigationContext {
  caseId: string;
  tenantId: string | null;
  // Searches are relative to when the case's activity began.
  anchor: Date;
  quarantine: LlmProvider | null;
  refs: EvidenceRef[];
  entities: CaseEntities;
  injection: InjectionFinding[];
  // Q-ref → event id, for get_event_details.
  events: Map<string, string>;
}

export function newContext(base: { caseId: string; tenantId: string | null; anchor: Date; quarantine: LlmProvider | null; entities: CaseEntities }): InvestigationContext {
  return { ...base, entities: structuredClone(base.entities), refs: [], injection: [], events: new Map() };
}

const HOUR = 3_600_000;
const clamp = (n: number | null | undefined, lo: number, hi: number, d: number) => (n == null || !Number.isFinite(n) ? d : Math.min(hi, Math.max(lo, Math.round(n))));

function ref(ctx: InvestigationContext, kind: EvidenceRef["kind"], text: string) {
  const r = `Q${ctx.refs.length + 1}`;
  ctx.refs.push({ ref: r, kind, text });
  return r;
}

function add(ctx: InvestigationContext, key: keyof CaseEntities, value: string | null | undefined) {
  const v = value?.trim();
  if (!v) return;
  const list = ctx.entities[key];
  if (!list.some((x) => x.toLowerCase() === v.toLowerCase())) list.push(key === "hashes" || key === "emails" ? v.toLowerCase() : v);
}

// A short field written on the client's systems: escaped, or withheld when
// it addresses the AI.
function field(ctx: InvestigationContext, where: string, value: string | null | undefined, max = 300): string {
  if (!value) return "";
  const found = scanText(where, value);
  if (found.length) {
    ctx.injection.push(...found);
    return "[withheld: text aimed at the AI]";
  }
  const clean = escapeUntrusted(value);
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

const wrap = (tool: string, body: string) => `<untrusted_tool_output tool="${tool}">\n${body || "(nothing found)"}\n</untrusted_tool_output>`;
const stamp = (d: Date) => d.toISOString().slice(0, 19).replace("T", " ");

// ---------------------------------------------------------------- definitions

const hours = (what: string) => z.number().int().nullable().describe(`${what}; null for the default`);

export const TOOL_INPUTS = {
  search_events: z.object({
    host: z.string().nullable().describe("Host name, exact (case-insensitive)"),
    user: z.string().nullable().describe("Account name, exact (case-insensitive)"),
    ip: z.string().nullable().describe("IP address, as source or destination"),
    process: z.string().nullable().describe("Part of a process name"),
    event_type: z.string().nullable().describe("Event type, exact"),
    hours_before: hours("Hours before the case's activity began to search from (0-168, default 24)"),
    hours_after: hours("Hours after it to search to (0-72, default 24)"),
    limit: z.number().int().nullable().describe("Most events to return (1-50, default 25)"),
  }),
  event_summary: z.object({
    host: z.string().nullable(),
    user: z.string().nullable(),
    ip: z.string().nullable(),
    hours_before: hours("Hours before the case's activity began (0-168, default 72)"),
    hours_after: hours("Hours after it (0-72, default 24)"),
  }),
  get_event_details: z.object({ ref: z.string().describe("A Q-id returned by search_events") }),
  get_endpoint: z.object({ hostname: z.string() }),
  lookup_indicator: z.object({ value: z.string().describe("An IP, domain, URL, email address or file hash") }),
  related_cases: z.object({}),
  get_technique: z.object({ id: z.string().describe("ATT&CK id such as T1059.001") }),
} as const;

export type ToolName = keyof typeof TOOL_INPUTS;

export const TOOL_DESCRIPTIONS: Record<ToolName, string> = {
  search_events: "Search this client's telemetry around the case: events for a host, account, IP, process or event type, oldest first. Give at least one filter. Returns evidence ids (Q…) for each event.",
  event_summary: "Count a host's, account's or IP's activity by event type and list who it talked to, over a window around the case. Give exactly one of host, user or ip. Cheaper than reading events one by one.",
  get_event_details: "The full record of one event returned by search_events (by its Q-id): every field the source sent. Long free text in it is reduced to the indicators and behaviours it contains.",
  get_endpoint: "What the client's inventory knows about a host: OS, IP, owner, type, criticality, protection controls, whether it's isolated and when it was last seen.",
  lookup_indicator: "The SOC's reputation record for an IP, domain, URL, email address or hash, how many of this client's cases it appears in, and how often it shows up in their telemetry in the last 30 days.",
  related_cases: "Earlier cases of this client that share hosts, accounts, indicators or techniques with this one, with why they're related and how they ended.",
  get_technique: "The ATT&CK technique's name and tactic.",
};

// ---------------------------------------------------------------- the tools

function window(ctx: InvestigationContext, before: number, after: number) {
  return { gte: new Date(ctx.anchor.getTime() - before * HOUR), lte: new Date(ctx.anchor.getTime() + after * HOUR) };
}

async function searchEvents(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.search_events>) {
  const where: Prisma.SecurityEventWhereInput = { tenantId: ctx.tenantId, timestamp: window(ctx, clamp(input.hours_before, 0, 168, 24), clamp(input.hours_after, 0, 72, 24)) };
  const and: Prisma.SecurityEventWhereInput[] = [];
  if (input.host) and.push({ hostName: { equals: input.host.trim(), mode: "insensitive" } });
  if (input.user) and.push({ userName: { equals: input.user.trim(), mode: "insensitive" } });
  if (input.ip) and.push({ OR: [{ sourceIp: input.ip.trim() }, { destIp: input.ip.trim() }] });
  if (input.process) and.push({ processName: { contains: input.process.trim(), mode: "insensitive" } });
  if (input.event_type) and.push({ eventType: input.event_type.trim() });
  if (!and.length) throw new Error("Give at least one of host, user, ip, process or event_type");
  where.AND = and;
  const limit = clamp(input.limit, 1, 50, 25);
  const [total, events] = await Promise.all([db.securityEvent.count({ where }), db.securityEvent.findMany({ where, orderBy: { timestamp: "asc" }, take: limit })]);
  const lines = events.map((e) => {
    const parts = [
      stamp(e.timestamp),
      e.eventType,
      e.hostName && `host=${field(ctx, "host", e.hostName, 120)}`,
      e.userName && `user=${field(ctx, "user", e.userName, 120)}`,
      e.processName && `proc=${field(ctx, "process", e.processName, 160)}${e.processPid != null ? `(${e.processPid})` : ""}`,
      e.parentProcessName && `parent=${field(ctx, "parent", e.parentProcessName, 160)}`,
      e.commandLine && e.commandLine !== e.processName && `cmd=${field(ctx, "command line", e.commandLine)}`,
      e.sourceIp && `src=${e.sourceIp}`,
      e.destIp && `dst=${e.destIp}${e.destPort ? `:${e.destPort}` : ""}`,
      e.filePath && `file=${field(ctx, "file path", e.filePath, 200)}`,
      e.fileHash && `sha256=${e.fileHash}`,
      e.geo && `geo=${field(ctx, "geo", e.geo, 60)}`,
    ].filter(Boolean);
    const line = parts.join(" ");
    const r = ref(ctx, "event", line);
    ctx.events.set(r, e.id);
    add(ctx, "hosts", e.hostName);
    add(ctx, "users", e.userName);
    add(ctx, "ips", e.sourceIp);
    add(ctx, "ips", e.destIp);
    add(ctx, "hashes", e.fileHash);
    if (e.processName) add(ctx, "processes", e.processName.split(/[\\/]/).pop());
    return `${r}: ${line}`;
  });
  return wrap("search_events", `${lines.join("\n")}${total > events.length ? `\n(${events.length} of ${total} matching events; narrow the window or add filters for the rest)` : ""}`);
}

async function eventSummary(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.event_summary>) {
  const given = [input.host, input.user, input.ip].filter(Boolean);
  if (given.length !== 1) throw new Error("Give exactly one of host, user or ip");
  const where: Prisma.SecurityEventWhereInput = {
    tenantId: ctx.tenantId,
    timestamp: window(ctx, clamp(input.hours_before, 0, 168, 72), clamp(input.hours_after, 0, 72, 24)),
    ...(input.host ? { hostName: { equals: input.host.trim(), mode: "insensitive" } } : {}),
    ...(input.user ? { userName: { equals: input.user.trim(), mode: "insensitive" } } : {}),
    ...(input.ip ? { OR: [{ sourceIp: input.ip.trim() }, { destIp: input.ip.trim() }] } : {}),
  };
  const by = async (column: "eventType" | "hostName" | "userName" | "destIp" | "sourceIp") =>
    (await db.securityEvent.groupBy({ by: [column], where: { ...where, NOT: { [column]: null } }, _count: true, orderBy: { _count: { [column]: "desc" } }, take: 10 })).map((r) => ({ value: String((r as Record<string, unknown>)[column]), n: r._count }));
  const total = await db.securityEvent.count({ where });
  const [types, a, b] = await Promise.all([by("eventType"), by(input.host ? "userName" : "hostName"), by(input.ip ? "userName" : "destIp")]);
  const who = input.host ? `host ${field(ctx, "host", input.host, 120)}` : input.user ? `account ${field(ctx, "user", input.user, 120)}` : `IP ${input.ip}`;
  const list = (rows: Array<{ value: string; n: number }>, label: string, key: keyof CaseEntities) => {
    rows.forEach((r) => add(ctx, key, r.value));
    return rows.length ? `${label}: ${rows.map((r) => `${field(ctx, label, r.value, 120)} (${r.n})`).join(", ")}` : "";
  };
  const line = [
    `${who}: ${total} events`,
    types.length ? `by type: ${types.map((t) => `${field(ctx, "event type", t.value, 60)} ${t.n}`).join(", ")}` : "",
    list(a, input.host ? "accounts" : "hosts", input.host ? "users" : "hosts"),
    list(b, input.ip ? "accounts" : "destinations", input.ip ? "users" : "ips"),
  ].filter(Boolean).join("; ");
  const r = ref(ctx, "context", line);
  return wrap("event_summary", `${r}: ${line}`);
}

function leaves(value: unknown, path = "", out: Array<[string, unknown]> = []): Array<[string, unknown]> {
  if (out.length >= 80) return out;
  if (value && typeof value === "object" && !Array.isArray(value)) for (const [k, v] of Object.entries(value)) leaves(v, path ? `${path}.${k}` : k, out);
  else if (Array.isArray(value)) value.slice(0, 10).forEach((v, i) => leaves(v, `${path}[${i}]`, out));
  else if (value !== null && value !== undefined && value !== "") out.push([path, value]);
  return out;
}

async function eventDetails(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.get_event_details>) {
  const id = ctx.events.get(input.ref.trim().toUpperCase());
  if (!id) throw new Error(`${input.ref} isn't an event returned by search_events in this investigation`);
  const e = await db.securityEvent.findFirst({ where: { id, tenantId: ctx.tenantId }, select: { ocsf: true, metadata: true, source: true, platform: true, eventType: true, timestamp: true } });
  if (!e) throw new Error("That event is gone");
  const lines: string[] = [`${input.ref}: ${stamp(e.timestamp)} ${e.eventType} from ${e.platform ?? e.source}`];
  for (const [path, v] of leaves(e.ocsf ?? e.metadata ?? {})) {
    if (typeof v === "string" && v.length > 200) {
      const facts = await extractFacts(v, ctx.quarantine);
      facts.ips.forEach((x) => add(ctx, "ips", x));
      facts.domains.forEach((x) => add(ctx, "domains", x));
      facts.emails.forEach((x) => add(ctx, "emails", x));
      facts.hashes.forEach((x) => add(ctx, "hashes", x));
      if (facts.behaviours.includes("addresses_an_ai")) ctx.injection.push({ ref: input.ref, kind: "verdict_steering", excerpt: `${path} (free text)` });
      lines.push(`${path} = ${renderFacts(facts)}`);
    } else {
      lines.push(`${path} = ${typeof v === "string" ? field(ctx, path, v, 200) : String(v)}`);
    }
  }
  const r = ref(ctx, "event", lines.join(" | ").slice(0, 600));
  return wrap("get_event_details", `${r} (details of ${input.ref})\n${lines.join("\n")}`);
}

async function endpoint(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.get_endpoint>) {
  const e = await db.endpoint.findFirst({ where: { tenantId: ctx.tenantId, hostname: { equals: input.hostname.trim(), mode: "insensitive" } } });
  if (!e) return wrap("get_endpoint", `${input.hostname} isn't in the client's inventory (an unmanaged or unknown host).`);
  add(ctx, "hosts", e.hostname);
  add(ctx, "ips", e.ipAddress);
  const controls = Object.entries(parseProtections(e.protections)).map(([k, c]) => `${k}=${c?.status}${c?.product ? `(${field(ctx, "product", c.product, 40)})` : ""}`);
  const line = [
    `${e.hostname}`,
    e.os && `os=${field(ctx, "os", e.os, 80)}`,
    e.ipAddress && `ip=${e.ipAddress}`,
    e.owner && `owner=${field(ctx, "owner", e.owner, 80)}`,
    `type=${e.assetClass ?? "?"}/${e.assetType ?? "?"}`,
    `criticality=${e.criticality}`,
    controls.length ? `controls: ${controls.join(" ")}` : "no protection controls recorded",
    e.isolated ? `ISOLATED since ${e.isolatedAt ? stamp(e.isolatedAt) : "?"}` : "not isolated",
    e.lastSeenAt ? `last seen ${stamp(e.lastSeenAt)}` : "never seen",
  ].filter(Boolean).join(" · ");
  const r = ref(ctx, "context", line);
  return wrap("get_endpoint", `${r}: ${line}`);
}

function indicatorType(v: string): "IP" | "DOMAIN" | "URL" | "FILE_HASH" | "EMAIL_ADDRESS" | null {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return "IP";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "FILE_HASH";
  if (/^https?:\/\//i.test(v)) return "URL";
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "EMAIL_ADDRESS";
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return "DOMAIN";
  return null;
}

async function indicator(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.lookup_indicator>) {
  const value = input.value.trim();
  const type = indicatorType(value);
  if (!type) throw new Error("That isn't an IP, domain, URL, email address or hash");
  const since = new Date(ctx.anchor.getTime() - 30 * 24 * HOUR);
  const [row, sightings] = await Promise.all([
    db.threatIndicator.findFirst({ where: { type, value: { equals: type === "FILE_HASH" ? value.toLowerCase() : value, mode: "insensitive" } }, include: { caseLinks: { where: { case: { tenantId: ctx.tenantId } }, select: { caseId: true } } } }),
    type === "IP" ? db.securityEvent.count({ where: { tenantId: ctx.tenantId, timestamp: { gte: since }, OR: [{ sourceIp: value }, { destIp: value }] } })
      : type === "FILE_HASH" ? db.securityEvent.count({ where: { tenantId: ctx.tenantId, timestamp: { gte: since }, fileHash: { equals: value, mode: "insensitive" } } })
        : Promise.resolve(null),
  ]);
  if (type === "IP") add(ctx, "ips", value);
  if (type === "FILE_HASH") add(ctx, "hashes", value);
  if (type === "DOMAIN") add(ctx, "domains", value);
  if (type === "EMAIL_ADDRESS") add(ctx, "emails", value);
  const line = [
    `${type.toLowerCase().replace("_", " ")} ${field(ctx, "indicator", value, 200)}`,
    row ? `reputation ${row.maliciousScore != null ? row.maliciousScore.toFixed(2) : "unknown"}${row.sources.length ? ` (${row.sources.join(", ")})` : ""}, checked ${stamp(row.lastCheckedAt)}` : "not in the SOC's indicator store",
    row?.blockedAt ? `blocked ${stamp(row.blockedAt)}` : null,
    row ? `in ${new Set(row.caseLinks.map((l) => l.caseId)).size} of this client's cases` : null,
    sightings != null ? `${sightings} events in the last 30 days` : null,
  ].filter(Boolean).join("; ");
  const r = ref(ctx, "indicator", line);
  return wrap("lookup_indicator", `${r}: ${line}`);
}

async function related(ctx: InvestigationContext) {
  const rows = await findRelatedCases(ctx.caseId, { limit: 6 });
  const lines = rows.map((c) => {
    const line = `${stamp(c.createdAt)} "${field(ctx, "case title", c.title, 140)}" ${c.severity.toLowerCase()} ${c.status.toLowerCase()}${c.verdict ? ` verdict=${c.verdict}` : ""} — ${c.reasons.slice(0, 3).map((x) => field(ctx, "reason", x, 80)).join("; ")}${c.rootCauseNarrative ? ` — root cause: ${field(ctx, "root cause", c.rootCauseNarrative, 240)}` : ""}`;
    return `${ref(ctx, "context", line)}: ${line}`;
  });
  return wrap("related_cases", lines.join("\n"));
}

function technique(ctx: InvestigationContext, input: z.infer<typeof TOOL_INPUTS.get_technique>) {
  const t = getTechnique(input.id.trim().toUpperCase());
  if (!t) return wrap("get_technique", `${input.id} isn't in HELIOS's ATT&CK reference set.`);
  return wrap("get_technique", `${t.id} ${t.name} (tactic: ${getTactic(t.tactic)?.name ?? t.tactic})`);
}

export async function runTool(ctx: InvestigationContext, name: string, input: unknown): Promise<string> {
  if (!(name in TOOL_INPUTS)) throw new Error(`No tool called ${name}`);
  const parsed = TOOL_INPUTS[name as ToolName].safeParse(input);
  if (!parsed.success) throw new Error(`Invalid input: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join(".") || "input"} ${i.message}`).join("; ")}`);
  const i = parsed.data as never;
  switch (name as ToolName) {
    case "search_events":
      return searchEvents(ctx, i);
    case "event_summary":
      return eventSummary(ctx, i);
    case "get_event_details":
      return eventDetails(ctx, i);
    case "get_endpoint":
      return endpoint(ctx, i);
    case "lookup_indicator":
      return indicator(ctx, i);
    case "related_cases":
      return related(ctx);
    case "get_technique":
      return technique(ctx, i);
  }
}

// A Zod schema as a strict tool's JSON Schema: closed objects, every field
// required (optional ones are nullable), no numeric or length bounds (the
// tools clamp them instead).
export function toolSchema(schema: z.ZodType): Record<string, unknown> {
  const strip = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(strip);
    if (!node || typeof node !== "object") return node;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      if (["$schema", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems", "pattern", "format"].includes(k)) continue;
      out[k] = strip(v);
    }
    return out;
  };
  return strip(z.toJSONSchema(schema)) as Record<string, unknown>;
}
