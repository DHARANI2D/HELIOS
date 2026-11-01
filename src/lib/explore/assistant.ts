import { z } from "zod";

import { db } from "@/lib/db";
import { resolveAgent } from "@/lib/ai/resolve";
import { usageColumns } from "@/lib/ai/provider";
import { FIELDS, RANGES, parseQuery, type RangeKey } from "@/lib/explore/query";

// The search assistant: a question in plain words becomes an Explore
// search. It runs on the model the client chose for it (lib/ai/gateway:
// the client's rules on providers and residency apply), and falls back to
// a built-in translator. It only writes the search: the model sees the
// question and the field list, never the client's logs, and what it
// returns is parsed like anything typed in the box before it runs.

export interface SearchSuggestion {
  query: string;
  range: RangeKey | null;
  explanation: string;
  engine: string;
  model: string | null;
  note?: string;
}

const RANGE_KEYS = Object.keys(RANGES) as [RangeKey, ...RangeKey[]];

const OutputSchema = z.object({
  query: z.string().max(2000).describe("The Explore search"),
  range: z.enum(["none", ...RANGE_KEYS]).describe('The time range the question asks for, or "none"'),
  explanation: z.string().max(600).describe("One or two sentences: what the search finds"),
});

const EVENT_TYPES = ["LOGIN_SUCCESS", "LOGIN_FAIL", "LOGIN_OTHER", "PROCESS_START", "PROCESS_END", "PROCESS_ACCESS", "PROCESS_INJECT", "FILE_CREATE", "FILE_MODIFY", "FILE_DELETE", "FILE_RENAME", "FILE_READ", "DNS_QUERY", "CONN_ALLOWED", "CONN_DENIED", "SERVICE_INSTALL", "CLOUD_ACTION"];

const SYSTEM = `You turn a security analyst's question into one search in HELIOS Explore, a log search over a client's security events.

Syntax:
- field:value (case-insensitive; * is a wildcard: process:*powershell*). Quote values with spaces: cmd:"net user".
- Terms side by side must all match. OR between two terms means either: type:LOGIN_FAIL OR type:LOGIN_SUCCESS.
- -field:value or NOT field:value excludes. field:* means it has a value; -field:* means it has none.
- Numbers compare: port:>1024, port:<=443. A comma list means any of: ip:1.2.3.4,5.6.7.8.
- A bare word or "quoted phrase" searches everywhere in the event.

Fields:
${FIELDS.map((f) => `- ${f.key}: ${f.label} (e.g. ${f.example})`).join("\n")}

Event types in use: ${EVENT_TYPES.join(", ")}.
Time ranges: ${RANGE_KEYS.join(", ")}; the range is separate from the search, never put time in the query.

Write the narrowest search that answers the question. Use only these fields and this syntax. Never invent values the question doesn't give.`;

// ---------------------------------------------------------------- built-in

const STOP = new Set("a an and any are as at by for from get give had has have in into is it list me my of on or show shows that the their them there these this those to was were what when where which who with all events event logs log find search any".split(" "));

export function builtinSuggestion(question: string): Omit<SearchSuggestion, "engine" | "model"> {
  const q = question.trim();
  const lower = q.toLowerCase();
  const terms: string[] = [];
  const used = new Set<string>();
  const take = (word: string) => used.add(word.toLowerCase());

  // Time.
  let range: RangeKey | null = null;
  const t = /\b(?:last|past)\s+(\d+)?\s*(minute|min|hour|hr|day|week|month)s?\b/.exec(lower);
  if (t) {
    const n = Number(t[1] ?? 1);
    const unit = t[2].startsWith("min") ? 60_000 : t[2].startsWith("h") ? 3_600_000 : t[2] === "day" ? 86_400_000 : t[2] === "week" ? 7 * 86_400_000 : 30 * 86_400_000;
    const ms = n * unit;
    range = (RANGE_KEYS.find((k) => RANGES[k].ms >= ms) ?? "90d") as RangeKey;
  } else if (/\btoday\b|\bsince yesterday\b/.test(lower)) range = "24h";
  else if (/\bthis week\b/.test(lower)) range = "7d";
  else if (/\bthis month\b/.test(lower)) range = "30d";

  // Kinds of activity.
  if (/\bfail(ed|ure|ing)?\b.*\b(log ?ins?|sign[- ]?ins?|logons?|auth\w*)\b|\b(log ?ins?|sign[- ]?ins?|logons?)\b.*\bfail/.test(lower)) terms.push("type:LOGIN_FAIL");
  else if (/\b(successful|succeeded)\b.*\b(log ?ins?|sign[- ]?ins?|logons?)\b/.test(lower)) terms.push("type:LOGIN_SUCCESS");
  else if (/\b(log ?ins?|sign[- ]?ins?|logons?)\b/.test(lower)) terms.push("type:LOGIN_SUCCESS OR type:LOGIN_FAIL");
  if (/\bdns\b/.test(lower)) terms.push("type:DNS_QUERY");
  if (/\b(blocked|denied)\b.*\bconnections?\b|\bconnections?\b.*\b(blocked|denied)\b/.test(lower)) terms.push("type:CONN_DENIED");
  if (/\bservices?\b.*\binstall/.test(lower)) terms.push("type:SERVICE_INSTALL");
  if (/\bprocess(es)?\b.*\b(start|launch|ran|run)|\b(start|launch)\w*\b.*\bprocess/.test(lower)) terms.push("type:PROCESS_START");
  if (/\bencoded\b/.test(lower)) terms.push('cmd:"*-enc*"');

  // Things it names.
  for (const ip of q.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []) {
    terms.push(`ip:${ip}`);
    take(ip);
  }
  for (const h of q.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) ?? []) {
    terms.push(`hash:${h}`);
    take(h);
  }
  const port = /\bport\s+(\d{1,5})\b/i.exec(q);
  if (port) {
    terms.push(`port:${port[1]}`);
    take(port[1]);
  }
  for (const p of q.match(/\b[\w.-]+\.(?:exe|dll|ps1|bat|vbs|js|hta|scr)\b/gi) ?? []) {
    terms.push(`process:*${p.toLowerCase()}*`);
    take(p);
  }
  for (const tool of ["powershell", "mimikatz", "psexec", "rundll32", "regsvr32", "certutil", "mshta", "wmic", "bitsadmin", "cmd"]) {
    if (new RegExp(`\\b${tool}\\b`, "i").test(q) && !terms.some((x) => x.includes(tool))) {
      terms.push(`process:*${tool}*`);
      take(tool);
    }
  }
  const host = /\b(?:host|machine|device|laptop|server|computer|endpoint)\s+([A-Za-z0-9][\w.-]*)/i.exec(q);
  if (host && !STOP.has(host[1].toLowerCase())) {
    terms.push(`host:${host[1]}*`);
    take(host[1]);
  }
  const user = /\b(?:user|account|by)\s+([A-Za-z0-9][\w.@\\-]*)/i.exec(q);
  if (user && !STOP.has(user[1].toLowerCase()) && !/^(\d+|failed|successful)$/i.test(user[1])) {
    terms.push(`user:${user[1]}`);
    take(user[1]);
  }

  if (!terms.length) {
    // Nothing recognised: search for its distinctive words.
    const words = q.split(/[^\w.@\\-]+/).filter((w) => w.length > 2 && !STOP.has(w.toLowerCase()) && !used.has(w.toLowerCase()) && !/^(last|past|minutes?|hours?|days?|weeks?|months?|today|yesterday|\d+)$/i.test(w));
    terms.push(...words.slice(0, 4));
  }
  const query = terms.join(" ");
  return {
    query,
    range,
    explanation: query ? `Built-in translation: ${query}${range ? ` over the ${RANGES[range].label.toLowerCase()}` : ""}. Check it and adjust.` : "Couldn't work out a search from that; try naming a host, account, IP or event type.",
  };
}

// ---------------------------------------------------------------- with a model

export async function suggestSearch(question: string, scope: { tenantId: string | null; userId: string }): Promise<SearchSuggestion> {
  const q = question.trim().slice(0, 600);
  if (!q) throw new Error("Ask a question first");
  const builtin = { ...builtinSuggestion(q), engine: "built-in", model: null };
  const { profile, provider, resolution } = await resolveAgent("search", { tenantId: scope.tenantId, userId: scope.userId });
  if (!provider) return { ...builtin, note: resolution?.reason ?? (profile.enabled ? "No model is set up for the search assistant" : "The search assistant is switched off") };

  const started = Date.now();
  const log = (data: { status: string; output?: object; error?: string; usage?: object; model?: string | null }) =>
    db.aiRun
      .create({
        data: {
          agentKey: "search",
          trigger: "manual",
          tenantId: scope.tenantId,
          engine: provider.name,
          model: data.model ?? provider.model,
          isLocal: provider.isLocal,
          status: data.status,
          output: data.output ?? undefined,
          error: data.error ?? null,
          durationMs: Date.now() - started,
          resolution: resolution ? JSON.parse(JSON.stringify(resolution)) : undefined,
          ...usageColumns(data.usage ?? {}),
          requestedById: scope.userId,
        },
      })
      .catch((err) => console.error("[search assistant] couldn't log the run", err));

  try {
    const res = await provider.structured({
      schema: OutputSchema,
      schemaName: "explore_search",
      system: `${SYSTEM}${profile.instructions?.trim() ? `\n\nAdditional instructions from the SOC:\n${profile.instructions.trim()}` : ""}`,
      user: `Question: ${q}`,
      effort: "low",
    });
    const query = res.data.query.trim();
    // What the model wrote must be a valid search, like anything typed.
    try {
      parseQuery(query);
    } catch (err) {
      await log({ status: "fallback", output: { question: q, query }, error: `Invalid search: ${err instanceof Error ? err.message : String(err)}`, usage: res.usage, model: res.model });
      return { ...builtin, note: `${provider.name} wrote a search HELIOS couldn't read, so this is the built-in translation` };
    }
    const range = res.data.range === "none" ? null : res.data.range;
    await log({ status: "succeeded", output: { question: q, query, range }, usage: res.usage, model: res.model });
    return { query, range, explanation: res.data.explanation, engine: provider.name, model: res.model };
  } catch (err) {
    await log({ status: "fallback", output: { question: q }, error: (err instanceof Error ? err.message : String(err)).slice(0, 500) });
    return { ...builtin, note: `${provider.name} didn't answer, so this is the built-in translation` };
  }
}
