import { createHash } from "node:crypto";
import { load } from "js-yaml";

// Sigma rules (sigmahq.io): the open format detection engineers share. This
// compiles one rule into a matcher over HELIOS events. Pure.
//
// What's supported, and what isn't, is explicit: a rule using anything
// outside this subset is refused at import with the reason, never run with
// part of its logic missing.
// - Detection: maps (fields ANDed, a list of values ORed), lists of maps
//   (ORed), keyword lists (any field), null (field absent).
// - Values: case-insensitive, with * and ? wildcards and \ escapes.
// - Modifiers: contains, startswith, endswith, all, re (with i, m, s), cidr,
//   exists, cased, gt, gte, lt, lte, windash, base64, base64offset, wide /
//   utf16le (with base64 or base64offset).
// - Conditions: and, or, not, parentheses, "1 of x*", "all of x*", "1 of
//   them", "all of them".
// - Not supported: aggregations ("| count() > 5"), correlation rules,
//   fieldref, expand placeholders.

export const LEVELS = ["informational", "low", "medium", "high", "critical"] as const;
export type SigmaLevel = (typeof LEVELS)[number];

// What a rule is matched against: the values each field has on the event,
// looked up through the field mapping (lib/detections/sigma-fields.ts).
export interface SigmaEvent {
  values(field: string): string[];
  // Every value on the event, for keyword searches.
  all(): string[];
}

export interface CompiledSigma {
  sigmaId: string;
  title: string;
  description: string;
  level: SigmaLevel;
  status: string;
  logsource: { category?: string; product?: string; service?: string };
  techniques: string[];
  tactics: string[];
  falsepositives: string[];
  fields: string[];
  match(event: SigmaEvent): boolean;
}

export type CompileResult = { ok: true; rule: CompiledSigma } | { ok: false; errors: string[] };

// ---------------------------------------------------------------- values

type Matcher = (event: SigmaEvent) => boolean;
type ValueTest = (value: string) => boolean;

const MODIFIERS = new Set(["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "cidr", "exists", "cased", "gt", "gte", "lt", "lte", "windash", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16"]);

// A Sigma value with wildcards as a regular expression source.
function wildcard(value: string): string {
  let out = "";
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === "\\" && i + 1 < value.length && "*?\\".includes(value[i + 1])) {
      out += value[i + 1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      i++;
    } else if (c === "*") out += ".*";
    else if (c === "?") out += ".";
    else out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}

function ipv4ToInt(ip: string): number | null {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function cidrTest(cidr: string): ValueTest {
  const [base, bits] = cidr.split("/");
  const start = ipv4ToInt(base);
  const n = Number(bits ?? 32);
  if (start === null || !Number.isInteger(n) || n < 0 || n > 32) throw new Error(`"${cidr}" isn't an IPv4 CIDR range (IPv6 isn't supported)`);
  const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
  return (v) => {
    const x = ipv4ToInt(v);
    return x !== null && (x & mask) >>> 0 === (start & mask) >>> 0;
  };
}

// windash: a leading - in command-line flags may also be /, –, — or ―.
const windash = (v: string) => [...new Set(["-", "/", "–", "—", "―"].map((d) => v.replace(/(^|\s)-/g, `$1${d}`)))];

function encode(value: string, wide: "utf16le" | "utf16be" | null): Buffer {
  if (wide === "utf16be") return Buffer.from(Buffer.from(value, "utf16le").swap16());
  return Buffer.from(value, wide ? "utf16le" : "utf8");
}

// base64offset: the three encodings a value can have depending on where it
// starts in the encoded stream (Sigma's definition).
function base64offsets(raw: Buffer): string[] {
  const out: string[] = [];
  for (let i = 0; i < 3; i++) {
    const padded = Buffer.concat([Buffer.alloc(i), raw]);
    const b64 = padded.toString("base64");
    const start = [0, 2, 3][i];
    const endTrim = [0, 3, 2][(raw.length + i) % 3];
    out.push(b64.slice(start, b64.length - endTrim));
  }
  return out;
}

function valueTests(raw: unknown, mods: string[]): ValueTest[] {
  if (raw === null) throw new Error("internal: null handled by the caller");
  let values = [String(raw)];
  const cased = mods.includes("cased");
  const wide = mods.includes("wide") || mods.includes("utf16le") || mods.includes("utf16") ? "utf16le" : mods.includes("utf16be") ? "utf16be" : null;
  if (wide && !mods.includes("base64") && !mods.includes("base64offset")) throw new Error("wide/utf16 modifiers are supported only with base64 or base64offset");
  if (mods.includes("windash")) values = values.flatMap(windash);
  if (mods.includes("base64")) values = values.map((v) => encode(v, wide).toString("base64"));
  if (mods.includes("base64offset")) values = values.flatMap((v) => base64offsets(encode(v, wide)));

  if (mods.includes("re")) {
    const flags = `${mods.includes("i") ? "i" : ""}${mods.includes("m") ? "m" : ""}${mods.includes("s") ? "s" : ""}`;
    return values.map((v) => {
      let re: RegExp;
      try {
        re = new RegExp(v, flags);
      } catch {
        throw new Error(`"${v}" isn't a valid regular expression`);
      }
      return (x) => re.test(x);
    });
  }
  if (mods.includes("cidr")) return values.map(cidrTest);
  for (const op of ["gt", "gte", "lt", "lte"] as const) {
    if (mods.includes(op)) {
      return values.map((v) => {
        const n = Number(v);
        if (!Number.isFinite(n)) throw new Error(`"${v}" isn't a number for |${op}`);
        return (x) => {
          const m = Number(x);
          return Number.isFinite(m) && (op === "gt" ? m > n : op === "gte" ? m >= n : op === "lt" ? m < n : m <= n);
        };
      });
    }
  }
  const pre = mods.includes("contains") || mods.includes("endswith") ? ".*" : "";
  const post = mods.includes("contains") || mods.includes("startswith") ? ".*" : "";
  // Encoded values are literal: their * and ? aren't wildcards.
  const literal = mods.includes("base64") || mods.includes("base64offset");
  return values.map((v) => {
    const body = literal ? v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : wildcard(v);
    const re = new RegExp(`^${pre}${body}${post}$`, cased || literal ? "s" : "is");
    return (x) => re.test(x);
  });
}

function fieldMatcher(key: string, raw: unknown, warnings: Set<string>): Matcher {
  const [field, ...mods] = key.split("|").map((p) => p.trim());
  for (const m of mods) if (!MODIFIERS.has(m)) throw new Error(`The modifier |${m} isn't supported`);
  if (!field) throw new Error(`"${key}" has no field name`);
  warnings.add(field);
  const list = Array.isArray(raw) ? raw : [raw];
  if (mods.includes("exists")) {
    const want = list[0] === true || String(list[0]).toLowerCase() === "true";
    return (e) => (e.values(field).some((v) => v !== "") === want);
  }
  // null: the field is absent or empty.
  if (list.length === 1 && list[0] === null) return (e) => e.values(field).every((v) => v === "");
  if (list.some((v) => v !== null && typeof v === "object")) throw new Error(`"${key}" has a nested value Sigma doesn't allow`);
  const tests = list.map((v) => (v === null ? null : valueTests(v, mods)));
  const any = (e: SigmaEvent, ts: ValueTest[] | null) => {
    const vals = e.values(field);
    return ts === null ? vals.every((v) => v === "") : vals.some((v) => ts.some((t) => t(v)));
  };
  return mods.includes("all") ? (e) => tests.every((ts) => any(e, ts)) : (e) => tests.some((ts) => any(e, ts));
}

function keywordMatcher(words: unknown[]): Matcher {
  const tests = words.flatMap((w) => valueTests(w, ["contains"]));
  return (e) => {
    const all = e.all();
    return tests.some((t) => all.some((v) => t(v)));
  };
}

function searchMatcher(def: unknown, fields: Set<string>): Matcher {
  if (Array.isArray(def)) {
    if (def.every((d) => d && typeof d === "object" && !Array.isArray(d))) {
      const ms = def.map((d) => searchMatcher(d, fields));
      return (e) => ms.some((m) => m(e));
    }
    if (def.every((d) => d === null || typeof d !== "object")) return keywordMatcher(def);
    throw new Error("A search mixes maps and keywords");
  }
  if (def && typeof def === "object") {
    const ms = Object.entries(def as Record<string, unknown>).map(([k, v]) => fieldMatcher(k, v, fields));
    if (!ms.length) throw new Error("An empty search");
    return (e) => ms.every((m) => m(e));
  }
  if (typeof def === "string" || typeof def === "number") return keywordMatcher([def]);
  throw new Error("A search must be a map, a list of maps or a list of keywords");
}

// ---------------------------------------------------------------- conditions

type Token = { t: "and" | "or" | "not" | "(" | ")" | "of" | "them" | "all" | "one" | "id"; v?: string };

function tokenize(condition: string): Token[] {
  const out: Token[] = [];
  const re = /\s*(\(|\)|[A-Za-z0-9_*.\-]+)/y;
  let m: RegExpExecArray | null;
  let at = 0;
  const s = condition.trim();
  while (at < s.length) {
    re.lastIndex = at;
    m = re.exec(s);
    if (!m) throw new Error(`Can't read the condition near "${s.slice(at, at + 20)}"`);
    at = re.lastIndex;
    const w = m[1];
    const lw = w.toLowerCase();
    if (w === "(" || w === ")") out.push({ t: w });
    else if (lw === "and" || lw === "or" || lw === "not" || lw === "of" || lw === "them" || lw === "all") out.push({ t: lw });
    else if (w === "1") out.push({ t: "one" });
    else out.push({ t: "id", v: w });
  }
  return out;
}

function compileCondition(condition: string, searches: Map<string, Matcher>): Matcher {
  if (condition.includes("|")) throw new Error("Aggregations in the condition (\"| count() …\") aren't supported; use a correlation rule elsewhere");
  const tokens = tokenize(condition);
  let i = 0;
  const peek = () => tokens[i];
  const take = (t: Token["t"]) => {
    if (tokens[i]?.t !== t) throw new Error(`Expected ${t} in the condition "${condition}"`);
    return tokens[i++];
  };
  const pick = (pattern: string): Matcher[] => {
    const re = new RegExp(`^${wildcard(pattern)}$`);
    const ms = [...searches.entries()].filter(([k]) => pattern === "them" || re.test(k)).map(([, m]) => m);
    if (!ms.length) throw new Error(`"${pattern}" matches no search in the rule`);
    return ms;
  };
  const primary = (): Matcher => {
    const tok = peek();
    if (!tok) throw new Error(`The condition "${condition}" ends too early`);
    if (tok.t === "not") {
      i++;
      const inner = primary();
      return (e) => !inner(e);
    }
    if (tok.t === "(") {
      i++;
      const inner = orExpr();
      take(")");
      return inner;
    }
    if (tok.t === "one" || tok.t === "all") {
      i++;
      take("of");
      const target = peek();
      if (!target || (target.t !== "them" && target.t !== "id")) throw new Error(`"of" needs a search name or "them"`);
      i++;
      const ms = pick(target.t === "them" ? "them" : target.v!);
      return tok.t === "one" ? (e) => ms.some((m) => m(e)) : (e) => ms.every((m) => m(e));
    }
    if (tok.t === "id") {
      i++;
      const m = searches.get(tok.v!);
      if (!m) throw new Error(`The condition names "${tok.v}", which isn't a search in the rule`);
      return m;
    }
    throw new Error(`Unexpected "${tok.v ?? tok.t}" in the condition`);
  };
  const andExpr = (): Matcher => {
    let left = primary();
    while (peek()?.t === "and") {
      i++;
      const l = left;
      const r = primary();
      left = (e) => l(e) && r(e);
    }
    return left;
  };
  const orExpr = (): Matcher => {
    let left = andExpr();
    while (peek()?.t === "or") {
      i++;
      const l = left;
      const r = andExpr();
      left = (e) => l(e) || r(e);
    }
    return left;
  };
  const m = orExpr();
  if (i < tokens.length) throw new Error(`Unexpected "${tokens[i].v ?? tokens[i].t}" in the condition`);
  return m;
}

// ---------------------------------------------------------------- the rule

const TACTICS: Record<string, string> = {
  reconnaissance: "Reconnaissance", resource_development: "Resource Development", initial_access: "Initial Access", execution: "Execution", persistence: "Persistence",
  privilege_escalation: "Privilege Escalation", defense_evasion: "Defense Evasion", credential_access: "Credential Access", discovery: "Discovery", lateral_movement: "Lateral Movement",
  collection: "Collection", command_and_control: "Command and Control", exfiltration: "Exfiltration", impact: "Impact",
};

export function compileSigma(source: string): CompileResult {
  let doc: unknown;
  try {
    doc = load(source);
  } catch (err) {
    return { ok: false, errors: [`Not valid YAML: ${err instanceof Error ? err.message.split("\n")[0] : String(err)}`] };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, errors: ["A Sigma rule is a YAML map"] };
  const r = doc as Record<string, unknown>;
  const errors: string[] = [];
  if (r.correlation) errors.push("Correlation rules aren't supported, only detection rules");
  const title = typeof r.title === "string" ? r.title.trim() : "";
  if (!title) errors.push("The rule needs a title");
  const level = (typeof r.level === "string" ? r.level.toLowerCase() : "medium") as SigmaLevel;
  if (!(LEVELS as readonly string[]).includes(level)) errors.push(`level "${String(r.level)}" isn't a Sigma level`);
  const detection = r.detection as Record<string, unknown> | undefined;
  if (!detection || typeof detection !== "object") errors.push("The rule needs a detection section");
  const condition = detection?.condition;
  const conditions = Array.isArray(condition) ? condition : [condition];
  if (!condition || conditions.some((c) => typeof c !== "string")) errors.push("The detection needs a condition");
  if (errors.length) return { ok: false, errors };

  const fields = new Set<string>();
  const searches = new Map<string, Matcher>();
  for (const [name, def] of Object.entries(detection!)) {
    if (name === "condition" || name === "timeframe") continue;
    try {
      searches.set(name, searchMatcher(def, fields));
    } catch (err) {
      errors.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  if (detection!.timeframe) errors.push("timeframe belongs to aggregations, which aren't supported");
  let match: Matcher | null = null;
  if (!errors.length) {
    try {
      const ms = (conditions as string[]).map((c) => compileCondition(c, searches));
      match = (e) => ms.some((m) => m(e));
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  if (errors.length || !match) return { ok: false, errors };

  const tags = (Array.isArray(r.tags) ? r.tags : []).map((t) => String(t).toLowerCase());
  const techniques = [...new Set(tags.flatMap((t) => { const m = t.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/); return m ? [m[1].toUpperCase()] : []; }))];
  const tactics = [...new Set(tags.flatMap((t) => { const m = t.match(/^attack\.([a-z_-]+)$/); const k = m?.[1].replace(/-/g, "_"); return k && TACTICS[k] ? [TACTICS[k]] : []; }))];
  const ls = (r.logsource ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim().toLowerCase() : undefined);
  const id = typeof r.id === "string" && r.id.trim() ? r.id.trim() : `sha-${createHash("sha256").update(source).digest("hex").slice(0, 16)}`;
  return {
    ok: true,
    rule: {
      sigmaId: id,
      title,
      description: typeof r.description === "string" ? r.description.trim() : "",
      level,
      status: typeof r.status === "string" ? r.status : "experimental",
      logsource: { category: str(ls.category), product: str(ls.product), service: str(ls.service) },
      techniques,
      tactics,
      falsepositives: (Array.isArray(r.falsepositives) ? r.falsepositives : []).map(String),
      fields: [...fields],
      match,
    },
  };
}

// A YAML stream of several rules (--- separated), each compiled on its own.
export function splitRules(text: string): string[] {
  return text.split(/^---\s*$/m).map((s) => s.trim()).filter(Boolean);
}
