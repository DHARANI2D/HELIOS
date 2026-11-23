import { z } from "zod";

import { PII_KINDS, type PiiKind } from "@/lib/aisec/detectors";

// The guard policy for one AI system: what to look for at each stage of a
// request and what to do about it. Verdicts, mildest first:
//   allow   nothing to do;
//   watch   let it through, but record it (and count it towards an attack);
//   redact  let a masked version through;
//   block   stop it.
// A new system starts from the baseline: deny-by-default for tools,
// injection and jailbreaks blocked, credentials and high-risk identifiers
// masked. Packs add what an industry needs; the client edits the rest. Every
// change is a new version, in force on the next call. Pure.

export const VERDICTS = ["allow", "watch", "redact", "block"] as const;
export type Verdict = (typeof VERDICTS)[number];
export const VERDICT_RANK: Record<Verdict, number> = { allow: 0, watch: 1, redact: 2, block: 3 };
export const worst = (a: Verdict, b: Verdict): Verdict => (VERDICT_RANK[a] >= VERDICT_RANK[b] ? a : b);

export const STAGES = {
  prompt: "What a person sends the AI",
  retrieval: "Documents the AI is about to read (RAG)",
  tool_call: "A tool the AI wants to call",
  tool_output: "What a tool returned to the AI",
  output: "The AI's answer, before anyone sees it",
} as const;
export type Stage = keyof typeof STAGES;

const control = z.enum(["block", "watch", "off"]);
const data = z.enum(["redact", "block", "watch", "off"]);
export type ControlAction = z.infer<typeof control>;
export type DataAction = z.infer<typeof data>;

const argRule = z.object({
  arg: z.string().trim().min(1).max(80),
  test: z.enum(["matches", "not_matches", "one_of", "max"]),
  value: z.string().max(500),
});
export type ArgRule = z.infer<typeof argRule>;

const toolRule = z.object({
  // A tool's name, or a prefix ending in * (send_*).
  name: z.string().trim().min(1).max(80),
  action: z.enum(["allow", "watch", "confirm", "block"]),
  args: z.array(argRule).max(10).default([]),
  note: z.string().max(300).optional(),
});
export type ToolRule = z.infer<typeof toolRule>;

export const policySchema = z.object({
  injection: z.object({ prompt: control, retrieval: control, toolOutput: control }),
  jailbreak: control,
  promptExtraction: control,
  canary: control,
  pii: z.object({
    kinds: z.array(z.enum(Object.keys(PII_KINDS) as [PiiKind, ...PiiKind[]])).max(20),
    prompt: data,
    retrieval: data,
    toolCall: data,
    output: data,
  }),
  secrets: z.object({ prompt: data, toolCall: data, toolOutput: data, output: data }),
  topics: z.object({ blocked: z.array(z.string().trim().min(2).max(80)).max(50), action: control }),
  output: z.object({ activeContent: control, links: control, allowDomains: z.array(z.string().trim().toLowerCase().regex(/^[a-z0-9.-]+$/).max(120)).max(50) }),
  tools: z.object({
    default: z.enum(["allow", "watch", "block"]),
    rules: z.array(toolRule).max(100),
    // An agent that says what it's doing may use only that task's tools.
    tasks: z.array(z.object({ task: z.string().trim().min(1).max(80), tools: z.array(z.string().trim().min(1).max(80)).max(50) })).max(50),
  }),
  retrieval: z.object({ enforceAccess: z.boolean() }),
  limits: z.object({ maxInputChars: z.number().int().min(100).max(1_000_000), requestsPerMinute: z.number().int().min(1).max(100_000) }),
  packs: z.array(z.string().max(40)).max(10),
});
export type GuardPolicy = z.infer<typeof policySchema>;

export function baselinePolicy(): GuardPolicy {
  return {
    injection: { prompt: "block", retrieval: "block", toolOutput: "block" },
    jailbreak: "block",
    promptExtraction: "block",
    canary: "block",
    pii: { kinds: ["card", "aadhaar", "pan", "ssn", "iban"], prompt: "redact", retrieval: "redact", toolCall: "watch", output: "redact" },
    secrets: { prompt: "redact", toolCall: "block", toolOutput: "redact", output: "block" },
    topics: { blocked: [], action: "block" },
    output: { activeContent: "block", links: "watch", allowDomains: [] },
    tools: { default: "block", rules: [], tasks: [] },
    retrieval: { enforceAccess: true },
    limits: { maxInputChars: 20_000, requestsPerMinute: 120 },
    packs: ["baseline"],
  };
}

// A stored policy, read defensively: anything missing or invalid falls back
// to the baseline rather than to nothing.
export function readPolicy(raw: unknown): GuardPolicy {
  const base = baselinePolicy();
  if (!raw || typeof raw !== "object") return base;
  const merged = { ...base, ...(raw as object) };
  const parsed = policySchema.safeParse(merged);
  return parsed.success ? parsed.data : base;
}

// ---------------------------------------------------------------- packs

const DATA_RANK: Record<DataAction, number> = { off: 0, watch: 1, redact: 2, block: 3 };
const stricterData = (a: DataAction, b: DataAction) => (DATA_RANK[a] >= DATA_RANK[b] ? a : b);

const DESTRUCTIVE = String.raw`\brm\s+-[a-z]*r[a-z]*f|\bmkfs\b|\bdd\s+if=|\bshutdown\b|\breboot\b|\bformat\s+[a-z]:|\bdel\s+/[sq]|\bchmod\s+(-R\s+)?777\b|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|Set-MpPreference|Disable-|\bnet\s+user\b.*\/add|\breg\s+delete\b`;
const DESTRUCTIVE_SQL = String.raw`\b(drop|truncate|alter|grant|revoke)\b|\bdelete\s+from\b(?![\s\S]*\bwhere\b)`;

export interface Pack {
  label: string;
  description: string;
  apply(p: GuardPolicy): GuardPolicy;
}

const withRules = (p: GuardPolicy, rules: ToolRule[]): GuardPolicy => ({
  ...p,
  tools: { ...p.tools, rules: [...p.tools.rules, ...rules.filter((r) => !p.tools.rules.some((x) => x.name === r.name))] },
});

const addKinds = (p: GuardPolicy, kinds: PiiKind[]) => [...new Set([...p.pii.kinds, ...kinds])];

export const PACKS: Record<string, Pack> = {
  privacy: {
    label: "Privacy (DPDP / GDPR)",
    description: "Masks personal data in prompts, retrieved documents and answers (email, phone, ID and account numbers, dates of birth), and records it in tool calls.",
    apply: (p) => ({
      ...p,
      pii: { ...p.pii, kinds: addKinds(p, ["email", "phone", "card", "aadhaar", "pan", "ssn", "iban", "dob"]), prompt: stricterData(p.pii.prompt, "redact"), retrieval: stricterData(p.pii.retrieval, "redact"), output: stricterData(p.pii.output, "redact"), toolCall: stricterData(p.pii.toolCall, "watch") },
    }),
  },
  healthcare: {
    label: "Healthcare (patient data)",
    description: "Privacy, plus medical record numbers and ABHA IDs; patient identifiers can't leave through tools, and sending messages needs the person's confirmation.",
    apply: (p) => {
      const q = PACKS.privacy.apply(p);
      return withRules({ ...q, pii: { ...q.pii, kinds: addKinds(q, ["mrn", "abha"]), toolCall: stricterData(q.pii.toolCall, "block") } }, [
        { name: "send_*", action: "confirm", args: [], note: "Messages to patients or staff need the person's confirmation" },
        { name: "http_*", action: "block", args: [], note: "No calls to arbitrary web addresses from a clinical assistant" },
        { name: "upload_*", action: "block", args: [], note: "Nothing leaves for outside storage" },
      ]);
    },
  },
  finance: {
    label: "Financial services",
    description: "Card, IBAN and PAN numbers masked; payments, refunds and transfers need the person's confirmation, refunds capped.",
    apply: (p) =>
      withRules({ ...p, pii: { ...p.pii, kinds: addKinds(p, ["card", "iban", "pan"]), output: stricterData(p.pii.output, "redact") }, secrets: { ...p.secrets, output: "block" } }, [
        { name: "refund*", action: "confirm", args: [{ arg: "amount", test: "max", value: "10000" }], note: "Refunds over 10,000 are not for the assistant" },
        { name: "transfer*", action: "confirm", args: [], note: "Money movement needs the person's confirmation" },
        { name: "pay*", action: "confirm", args: [], note: "Payments need the person's confirmation" },
      ]),
  },
  it: {
    label: "Enterprise IT and DevOps",
    description: "Agents that run commands or queries: destructive commands and schema changes are blocked, credentials never leave in answers or tool calls.",
    apply: (p) =>
      withRules({ ...p, secrets: { ...p.secrets, output: "block", toolCall: "block" } }, [
        { name: "run_*", action: "watch", args: [{ arg: "command", test: "not_matches", value: DESTRUCTIVE }], note: "No destructive commands" },
        { name: "exec*", action: "watch", args: [{ arg: "command", test: "not_matches", value: DESTRUCTIVE }], note: "No destructive commands" },
        { name: "shell*", action: "watch", args: [{ arg: "command", test: "not_matches", value: DESTRUCTIVE }], note: "No destructive commands" },
        { name: "sql*", action: "watch", args: [{ arg: "query", test: "not_matches", value: DESTRUCTIVE_SQL }], note: "Read and targeted changes only; no schema changes or unbounded deletes" },
      ]),
  },
  strict: {
    label: "Strict (high-risk systems)",
    description: "Every control at its strictest: links in answers only to listed domains, personal data blocked rather than masked in answers.",
    apply: (p) => ({
      ...p,
      injection: { prompt: "block", retrieval: "block", toolOutput: "block" },
      jailbreak: "block",
      promptExtraction: "block",
      canary: "block",
      pii: { ...p.pii, output: "block" },
      secrets: { prompt: "block", toolCall: "block", toolOutput: "block", output: "block" },
      output: { ...p.output, activeContent: "block", links: "block" },
      tools: { ...p.tools, default: "block" },
    }),
  },
};

export function applyPack(p: GuardPolicy, pack: string): GuardPolicy {
  const def = PACKS[pack];
  if (!def) throw new Error(`Unknown pack: ${pack}`);
  const next = def.apply(p);
  return { ...next, packs: [...new Set([...p.packs, pack])] };
}

// The policy a new system starts with: the baseline, plus the packs its
// data calls for.
export function starterPolicy(dataClasses: readonly string[], kind: string): GuardPolicy {
  let p = baselinePolicy();
  if (dataClasses.includes("pii")) p = applyPack(p, "privacy");
  if (dataClasses.includes("phi")) p = applyPack(p, "healthcare");
  if (dataClasses.includes("pci")) p = applyPack(p, "finance");
  if (kind === "AGENT" && (dataClasses.includes("source_code") || dataClasses.includes("internal"))) p = applyPack(p, "it");
  return p;
}

// ---------------------------------------------------------------- recommendations

export interface Recommendation {
  id: string;
  title: string;
  why: string;
  apply(p: GuardPolicy): GuardPolicy;
}

// What to switch on after a red-team finding, keyed by OWASP category.
export function recommendationsFor(owasp: readonly string[], p: GuardPolicy): Recommendation[] {
  const out: Recommendation[] = [];
  const has = (id: string) => owasp.includes(id);
  if (has("LLM01") && (p.injection.prompt !== "block" || p.jailbreak !== "block")) {
    out.push({ id: "block-injection", title: "Block prompt injection and jailbreaks", why: "The red team got the AI to follow injected instructions or drop its rules.", apply: (q) => ({ ...q, injection: { ...q.injection, prompt: "block" }, jailbreak: "block" }) });
  }
  if (has("LLM01") && (p.injection.retrieval !== "block" || p.injection.toolOutput !== "block")) {
    out.push({ id: "block-indirect", title: "Block instructions hidden in documents and tool results", why: "Injected instructions also arrive through what the AI reads.", apply: (q) => ({ ...q, injection: { ...q.injection, retrieval: "block", toolOutput: "block" } }) });
  }
  if (has("LLM07") && (p.canary !== "block" || p.promptExtraction !== "block")) {
    out.push({ id: "block-leak", title: "Block system prompt extraction and leaks", why: "The system prompt (its canary) came out in an answer.", apply: (q) => ({ ...q, canary: "block", promptExtraction: "block" }) });
  }
  if (has("LLM02") && (p.secrets.output !== "block" || p.pii.output === "off" || p.pii.output === "watch")) {
    out.push({ id: "mask-output", title: "Mask personal data and block credentials in answers", why: "An answer disclosed personal data or a credential.", apply: (q) => ({ ...applyPack(q, "privacy"), secrets: { ...q.secrets, output: "block" } }) });
  }
  if (has("LLM05") && p.output.activeContent !== "block") {
    out.push({ id: "block-active", title: "Block scripts and active content in answers", why: "The AI returned markup an application could execute.", apply: (q) => ({ ...q, output: { ...q.output, activeContent: "block" } }) });
  }
  if (has("LLM06") && p.tools.default !== "block") {
    out.push({ id: "deny-tools", title: "Deny tools by default", why: "The AI claimed to take actions nobody confirmed.", apply: (q) => ({ ...q, tools: { ...q.tools, default: "block" } }) });
  }
  if (has("LLM10") && p.limits.maxInputChars > 20_000) {
    out.push({ id: "limit-input", title: "Cap prompt size at 20,000 characters", why: "Very large requests went through.", apply: (q) => ({ ...q, limits: { ...q.limits, maxInputChars: 20_000 } }) });
  }
  return out;
}

// ---------------------------------------------------------------- tools

export function toolMatches(pattern: string, name: string) {
  const p = pattern.toLowerCase();
  const n = name.toLowerCase();
  return p.endsWith("*") ? n.startsWith(p.slice(0, -1)) : p === n;
}

// An argument rule broken, or null. A pattern that doesn't compile counts
// as broken (fail closed).
export function argViolation(rule: ArgRule, args: Record<string, unknown>): string | null {
  const v = args[rule.arg];
  const s = v == null ? "" : typeof v === "string" ? v : JSON.stringify(v);
  if (rule.test === "max") {
    const n = typeof v === "number" ? v : Number(s);
    const limit = Number(rule.value);
    if (v == null) return null;
    return Number.isFinite(n) && n <= limit ? null : `${rule.arg} is ${s}, over the limit of ${rule.value}`;
  }
  if (rule.test === "one_of") {
    const allowed = rule.value.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    return v == null || allowed.includes(s.toLowerCase()) ? null : `${rule.arg} must be one of ${allowed.join(", ")}`;
  }
  let re: RegExp;
  try {
    re = new RegExp(rule.value, "i");
  } catch {
    return `the rule for ${rule.arg} has an invalid pattern`;
  }
  if (rule.test === "matches") return re.test(s) ? null : `${rule.arg} doesn't match what's allowed`;
  return re.test(s) ? `${rule.arg} contains something this tool may not do` : null;
}
