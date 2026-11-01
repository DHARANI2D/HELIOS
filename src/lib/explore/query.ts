// The Explore query language: one search box over every log HELIOS holds,
// in the style analysts know from Splunk, Chronicle, QRadar and Wazuh.
// Client-safe (no database access): the page uses it for help and to add
// filters when someone clicks a value.
//
//   host:FIN-WS-04 user:alice              both (terms are ANDed)
//   type:LOGIN_FAIL OR type:LOGIN_SUCCESS  either (OR joins neighbours)
//   process:*powershell* cmd:"-enc"        wildcards, quoted values
//   -user:svc_backup   NOT src:10.*        exclude
//   port:>1024 port:<=65535                numbers compare
//   ip:203.0.113.7,198.51.100.2            any of a list
//   hash:*   -case:*                       has a value / has none
//   mimikatz "lsass dump"                  free text, anywhere in the event
//
// It compiles to parameterised SQL (lib/explore/search.ts): values never
// become SQL, and the fields map to a fixed list of columns.

export type FieldKind = "text" | "int";

export interface FieldDef {
  key: string;
  label: string;
  columns: string[]; // more than one: matches any of them
  kind: FieldKind;
  example: string;
}

export const FIELDS: FieldDef[] = [
  { key: "host", label: "Host", columns: ["hostName"], kind: "text", example: "host:FIN-WS-04" },
  { key: "user", label: "Account", columns: ["userName"], kind: "text", example: "user:alice*" },
  { key: "ip", label: "Source or destination IP", columns: ["sourceIp", "destIp"], kind: "text", example: "ip:203.0.113.7" },
  { key: "src", label: "Source IP", columns: ["sourceIp"], kind: "text", example: "src:10.*" },
  { key: "dst", label: "Destination IP", columns: ["destIp"], kind: "text", example: "dst:198.51.100.2" },
  { key: "port", label: "Destination port", columns: ["destPort"], kind: "int", example: "port:>1024" },
  { key: "type", label: "Event type", columns: ["eventType"], kind: "text", example: "type:LOGIN_FAIL" },
  { key: "source", label: "Log source", columns: ["source"], kind: "text", example: "source:auth" },
  { key: "platform", label: "Product", columns: ["platform"], kind: "text", example: "platform:sysmon" },
  { key: "process", label: "Process", columns: ["processName"], kind: "text", example: "process:*powershell*" },
  { key: "parent", label: "Parent process", columns: ["parentProcessName"], kind: "text", example: "parent:winword.exe" },
  { key: "pid", label: "Process id", columns: ["processPid"], kind: "int", example: "pid:4242" },
  { key: "cmd", label: "Command line", columns: ["commandLine"], kind: "text", example: 'cmd:"*-enc*"' },
  { key: "file", label: "File path", columns: ["filePath"], kind: "text", example: "file:*\\Temp\\*" },
  { key: "hash", label: "File hash", columns: ["fileHash"], kind: "text", example: "hash:44d88612*" },
  { key: "service", label: "Service", columns: ["service"], kind: "text", example: "service:sshd" },
  { key: "severity", label: "Severity hint", columns: ["severityHint"], kind: "text", example: "severity:high" },
  { key: "geo", label: "Country", columns: ["geo"], kind: "text", example: "geo:RU" },
  { key: "class", label: "OCSF class", columns: ["classUid"], kind: "int", example: "class:3002" },
  { key: "case", label: "Case id", columns: ["caseId"], kind: "text", example: "case:*" },
  { key: "integration", label: "Integration id", columns: ["integrationId"], kind: "text", example: "integration:clx…" },
];

const ALIASES: Record<string, string> = {
  hostname: "host", username: "user", account: "user", srcip: "src", sourceip: "src", src_ip: "src", dstip: "dst", destip: "dst", dest_ip: "dst", dst_ip: "dst",
  dport: "port", destport: "port", dest_port: "port", dst_port: "port", event: "type", eventtype: "type", event_type: "type", proc: "process", processname: "process", image: "process",
  commandline: "cmd", command: "cmd", path: "file", filepath: "file", sha256: "hash", md5: "hash", sha1: "hash", country: "geo", product: "platform",
};

export function fieldFor(name: string): FieldDef | null {
  const k = name.toLowerCase();
  return FIELDS.find((f) => f.key === (ALIASES[k] ?? k)) ?? null;
}

export type Op = "eq" | "gt" | "gte" | "lt" | "lte" | "exists";

export type Term =
  | { kind: "field"; field: FieldDef; op: Op; values: string[]; negate: boolean }
  | { kind: "text"; value: string; negate: boolean };

// Terms in a group are ORed; groups are ANDed.
export type Query = Term[][];

export class QueryError extends Error {}

const MAX_LENGTH = 2000;
const MAX_TERMS = 40;
const MAX_LIST = 50;

function tokenize(input: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === "\\" && quoted && input[i + 1] === '"') {
      cur += '"';
      i++;
    } else if (ch === '"') {
      quoted = !quoted;
      cur += ch;
    } else if (!quoted && /\s/.test(ch)) {
      if (cur) out.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (quoted) throw new QueryError("A quote isn't closed");
  if (cur) out.push(cur);
  return out;
}

const unquote = (s: string) => (s.length >= 2 && s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s);

function parseTerm(token: string, negate: boolean): Term {
  const m = /^([A-Za-z_][A-Za-z0-9_]*):(.*)$/.exec(token);
  if (!m) {
    const value = unquote(token);
    if (!value) throw new QueryError("Empty search term");
    return { kind: "text", value, negate };
  }
  const field = fieldFor(m[1]);
  if (!field) throw new QueryError(`Unknown field "${m[1]}". Fields: ${FIELDS.map((f) => f.key).join(", ")}`);
  let rest = m[2];
  if (rest === "") throw new QueryError(`${field.key}: needs a value`);
  if (rest === "*") return { kind: "field", field, op: "exists", values: [], negate };
  let op: Op = "eq";
  const cmp = /^(>=|<=|>|<)(.*)$/.exec(rest);
  if (cmp) {
    if (field.kind !== "int") throw new QueryError(`${field.key} isn't a number, so it can't be compared with ${cmp[1]}`);
    op = ({ ">": "gt", ">=": "gte", "<": "lt", "<=": "lte" } as const)[cmp[1] as ">" | ">=" | "<" | "<="];
    rest = cmp[2];
  }
  const values = (rest.startsWith('"') ? [unquote(rest)] : rest.split(",")).map((v) => v.trim()).filter(Boolean);
  if (!values.length) throw new QueryError(`${field.key}: needs a value`);
  if (values.length > MAX_LIST) throw new QueryError(`${field.key}: at most ${MAX_LIST} values in a list`);
  if (field.kind === "int") {
    for (const v of values) if (!/^-?\d{1,10}$/.test(v)) throw new QueryError(`${field.key} takes whole numbers ("${v}" isn't one)`);
    if (op !== "eq" && values.length > 1) throw new QueryError(`${field.key}: compare with one number`);
  }
  return { kind: "field", field, op, values, negate };
}

export function parseQuery(input: string): Query {
  const text = input.trim();
  if (text.length > MAX_LENGTH) throw new QueryError(`The search is too long (at most ${MAX_LENGTH} characters)`);
  if (!text || text === "*") return [];
  const tokens = tokenize(text);
  const groups: Query = [];
  let joinNext = false;
  let negateNext = false;
  let count = 0;
  for (const raw of tokens) {
    if (raw === "OR") {
      if (!groups.length || joinNext || negateNext) throw new QueryError("OR needs a term on each side");
      joinNext = true;
      continue;
    }
    if (raw === "AND") continue;
    if (raw === "NOT") {
      negateNext = !negateNext;
      continue;
    }
    let token = raw;
    let negate = negateNext;
    if (token.startsWith("-") && token.length > 1) {
      negate = !negate;
      token = token.slice(1);
    }
    const term = parseTerm(token, negate);
    if (++count > MAX_TERMS) throw new QueryError(`At most ${MAX_TERMS} terms in one search`);
    if (joinNext) groups[groups.length - 1].push(term);
    else groups.push([term]);
    joinNext = false;
    negateNext = false;
  }
  if (joinNext) throw new QueryError("OR needs a term on each side");
  if (negateNext) throw new QueryError("NOT needs a term after it");
  return groups;
}

// A filter for one value, as the page adds it when someone clicks a value.
export function filterFor(field: string, value: string, negate = false): string {
  const v = /[\s",]/.test(value) || value === "" ? `"${value.replaceAll('"', '\\"')}"` : value;
  return `${negate ? "-" : ""}${field}:${v}`;
}

// Time ranges the page offers, and how wide each histogram bar is.
export const RANGES = {
  "15m": { label: "Last 15 minutes", ms: 15 * 60_000 },
  "1h": { label: "Last hour", ms: 3_600_000 },
  "4h": { label: "Last 4 hours", ms: 4 * 3_600_000 },
  "24h": { label: "Last 24 hours", ms: 24 * 3_600_000 },
  "7d": { label: "Last 7 days", ms: 7 * 86_400_000 },
  "30d": { label: "Last 30 days", ms: 30 * 86_400_000 },
  "90d": { label: "Last 90 days", ms: 90 * 86_400_000 },
} as const;
export type RangeKey = keyof typeof RANGES;

const STEPS = [1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86_400];

// About 60 bars across the window, on a round step.
export function bucketSeconds(fromMs: number, toMs: number): number {
  const want = Math.max(1, (toMs - fromMs) / 1000 / 60);
  return STEPS.find((s) => s >= want) ?? Math.ceil(want / 86_400) * 86_400;
}
