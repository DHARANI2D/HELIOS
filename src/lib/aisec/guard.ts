import {
  INJECTION_LABEL,
  findActiveContent,
  findCanary,
  findInjection,
  findJailbreak,
  findLinks,
  findPii,
  findSecrets,
  findTopics,
  hostAllowed,
  redact,
  safeExcerpt,
  type Hit,
} from "@/lib/aisec/detectors";
import { VERDICT_RANK, argViolation, toolMatches, worst, type ControlAction, type DataAction, type GuardPolicy, type Stage, type Verdict } from "@/lib/aisec/policy";

// The AI guard: one request at one stage, against the system's policy.
// Answers with a verdict, what it found (each mapped to the OWASP Top 10 for
// LLM applications and MITRE ATLAS), the masked content where it masked
// anything, and a plain-English reason. In monitor mode it decides the same
// but tells the caller to go ahead, so a client can watch what the policy
// would do before enforcing it. Pure.

export interface GuardRequest {
  stage: Stage;
  content?: string;
  tool?: { name: string; args: Record<string, unknown> };
  documents?: Array<{ id: string; text: string; access?: string[] }>;
  user?: { id?: string; roles?: string[] };
  task?: string;
  // The person confirmed a tool action that needs confirmation.
  confirmed?: boolean;
}

export interface GuardFinding {
  rule: string;
  verdict: Verdict;
  message: string;
  excerpt?: string;
  owasp: string[];
  atlas: string[];
}

export interface GuardResult {
  // What the policy decided, and what the caller must do (the same when enforcing).
  decision: Verdict;
  enforced: Verdict;
  findings: GuardFinding[];
  // The content to use instead (masked), when the decision is redact.
  content?: string;
  // Retrieval: the documents the AI may read, and the ones withheld.
  documents?: Array<{ id: string; text: string }>;
  withheld?: string[];
  needsConfirmation?: boolean;
  explanation: string;
}

export interface GuardContext {
  policy: GuardPolicy;
  mode: "enforce" | "monitor";
  canary: string;
}

const control = (a: ControlAction): Verdict | null => (a === "off" ? null : a);
const data = (a: DataAction): Verdict | null => (a === "off" ? null : a);

const INJECTION_ATLAS = { direct: ["AML.T0051.000"], indirect: ["AML.T0051.001"] };

class Collector {
  findings: GuardFinding[] = [];
  masks: Hit[] = [];
  add(f: GuardFinding) {
    this.findings.push(f);
  }
  get decision(): Verdict {
    return this.findings.reduce<Verdict>((d, f) => worst(d, f.verdict), "allow");
  }
}

function scanInjection(c: Collector, text: string, action: ControlAction, where: "prompt" | "content", source: string) {
  const v = control(action);
  if (!v) return;
  for (const h of findInjection(text, where)) {
    if (where === "prompt" && h.kind === "extraction") continue; // promptExtraction decides that one
    c.add({ rule: `injection.${h.kind}`, verdict: v, message: `${source} ${INJECTION_LABEL[h.kind]}`, excerpt: safeExcerpt(h.excerpt), owasp: ["LLM01"], atlas: where === "prompt" ? INJECTION_ATLAS.direct : INJECTION_ATLAS.indirect });
  }
}

function scanData(c: Collector, text: string, policy: GuardPolicy, pii: DataAction, secrets: DataAction, where: string, leak: boolean) {
  const s = data(secrets);
  if (s) {
    const hits = findSecrets(text);
    for (const label of [...new Set(hits.map((h) => h.label))]) {
      c.add({ rule: "secret", verdict: s, message: `${where} contains a credential (${label})`, owasp: ["LLM02"], atlas: leak ? ["AML.T0057"] : [] });
    }
    if (s === "redact") c.masks.push(...hits);
  }
  const p = data(pii);
  if (p && policy.pii.kinds.length) {
    const hits = findPii(text, policy.pii.kinds);
    const kinds = [...new Set(hits.map((h) => h.kind))];
    if (kinds.length) c.add({ rule: `pii.${kinds.join("+")}`, verdict: p, message: `${where} contains personal data (${kinds.join(", ")}: ${hits.length})`, owasp: ["LLM02"], atlas: leak ? ["AML.T0057"] : [] });
    if (p === "redact") c.masks.push(...hits);
  }
}

function scanTopics(c: Collector, text: string, policy: GuardPolicy, where: string) {
  const v = control(policy.topics.action);
  if (!v) return;
  const hit = findTopics(text, policy.topics.blocked);
  if (hit.length) c.add({ rule: "topic", verdict: v, message: `${where} is about a topic this assistant must not cover (${hit.slice(0, 3).join(", ")})`, owasp: [], atlas: [] });
}

const words = (n: number, unit: string) => `${n.toLocaleString("en-US")} ${unit}`;

export function evaluateGuard(ctx: GuardContext, req: GuardRequest): GuardResult {
  const { policy } = ctx;
  const c = new Collector();
  const text = req.content ?? "";
  let documents: GuardResult["documents"];
  let withheld: string[] | undefined;
  let needsConfirmation = false;

  if (text.length > policy.limits.maxInputChars && req.stage !== "output") {
    c.add({ rule: "limit.size", verdict: "block", message: `The ${req.stage.replace("_", " ")} is ${words(text.length, "characters")}, over the limit of ${words(policy.limits.maxInputChars, "")}`, owasp: ["LLM10"], atlas: ["AML.T0029"] });
  }

  switch (req.stage) {
    case "prompt": {
      scanInjection(c, text, policy.injection.prompt, "prompt", "The prompt");
      const jb = control(policy.jailbreak) && findJailbreak(text);
      if (jb) c.add({ rule: "jailbreak", verdict: control(policy.jailbreak)!, message: "The prompt tries to take the assistant's rules off (jailbreak)", excerpt: safeExcerpt(jb), owasp: ["LLM01"], atlas: ["AML.T0054"] });
      const ex = control(policy.promptExtraction) && findInjection(text, "prompt").find((h) => h.kind === "extraction");
      if (ex) c.add({ rule: "prompt_extraction", verdict: control(policy.promptExtraction)!, message: "The prompt asks for the system prompt or hidden instructions", excerpt: safeExcerpt(ex.excerpt), owasp: ["LLM07"], atlas: ["AML.T0056"] });
      scanTopics(c, text, policy, "The prompt");
      scanData(c, text, policy, policy.pii.prompt, policy.secrets.prompt, "The prompt", false);
      break;
    }
    case "tool_output": {
      scanInjection(c, text, policy.injection.toolOutput, "content", "The tool result");
      scanData(c, text, policy, policy.pii.retrieval, policy.secrets.toolOutput, "The tool result", false);
      break;
    }
    case "output": {
      const cv = control(policy.canary);
      if (cv && findCanary(text, ctx.canary)) c.add({ rule: "canary", verdict: cv, message: "The answer contains the system prompt's canary: the system prompt leaked", owasp: ["LLM07"], atlas: ["AML.T0056"] });
      scanData(c, text, policy, policy.pii.output, policy.secrets.output, "The answer", true);
      scanTopics(c, text, policy, "The answer");
      const av = control(policy.output.activeContent);
      if (av) {
        const active = findActiveContent(text);
        if (active.length) c.add({ rule: "output.active", verdict: av, message: `The answer contains ${[...new Set(active.map((a) => a.label))].join(", ")}, which an application could run`, excerpt: safeExcerpt(text.slice(Math.max(0, active[0].start - 20), active[0].end + 40)), owasp: ["LLM05"], atlas: [] });
      }
      const links = findLinks(text);
      // An image whose address carries data is how answers leak chats to a
      // third party: the browser fetches it without anyone clicking.
      const beacon = links.find((l) => l.image && /\?[^#]*=/.test(l.value) && !hostAllowed(l.host, policy.output.allowDomains));
      if (beacon && av) c.add({ rule: "output.exfiltration", verdict: av, message: `The answer embeds an image from ${beacon.host} with data in its address (a way to leak the conversation)`, excerpt: safeExcerpt(beacon.value), owasp: ["LLM05", "LLM02"], atlas: ["AML.T0057"] });
      const lv = control(policy.output.links);
      const foreign = [...new Set(links.filter((l) => !hostAllowed(l.host, policy.output.allowDomains)).map((l) => l.host))];
      if (lv && foreign.length && policy.output.allowDomains.length) c.add({ rule: "output.link", verdict: lv, message: `The answer links to ${foreign.slice(0, 3).join(", ")}, outside the allowed domains`, owasp: ["LLM05"], atlas: [] });
      else if (lv === "block" && foreign.length) c.add({ rule: "output.link", verdict: "block", message: `The answer links to ${foreign.slice(0, 3).join(", ")}; links are allowed only to listed domains, and none are listed`, owasp: ["LLM05"], atlas: [] });
      break;
    }
    case "tool_call": {
      const tool = req.tool;
      if (!tool?.name) {
        c.add({ rule: "tool.missing", verdict: "block", message: "A tool call without a tool name", owasp: ["LLM06"], atlas: [] });
        break;
      }
      const args = tool.args ?? {};
      const rule = policy.tools.rules.find((r) => toolMatches(r.name, tool.name));
      const scope = req.task ? policy.tools.tasks.find((t) => t.task.toLowerCase() === req.task!.toLowerCase()) : undefined;
      if (scope && !scope.tools.some((t) => toolMatches(t, tool.name))) {
        c.add({ rule: "tool.task_scope", verdict: "block", message: `${tool.name} isn't one of the tools for the task "${scope.task}" (the agent may have been steered off its task)`, owasp: ["LLM06", "LLM01"], atlas: ["AML.T0053"] });
      }
      if (!rule) {
        const d = policy.tools.default;
        if (d !== "allow") c.add({ rule: "tool.unlisted", verdict: d, message: d === "block" ? `${tool.name} isn't on this system's list of allowed tools (deny by default)` : `${tool.name} isn't on the list of tools; recorded`, owasp: ["LLM06"], atlas: d === "block" ? ["AML.T0053"] : [] });
      } else {
        const broken = rule.args.map((a) => argViolation(a, args)).filter((x): x is string => !!x);
        if (rule.action === "block") c.add({ rule: "tool.blocked", verdict: "block", message: `${tool.name} is blocked for this system${rule.note ? `: ${rule.note}` : ""}`, owasp: ["LLM06"], atlas: ["AML.T0053"] });
        else if (broken.length) c.add({ rule: "tool.argument", verdict: "block", message: `${tool.name}: ${broken.join("; ")}${rule.note ? ` (${rule.note})` : ""}`, owasp: ["LLM06"], atlas: ["AML.T0053"] });
        else if (rule.action === "confirm" && !req.confirmed) {
          needsConfirmation = true;
          c.add({ rule: "tool.confirm", verdict: "block", message: `${tool.name} needs the person's confirmation first${rule.note ? `: ${rule.note}` : ""}`, owasp: ["LLM06"], atlas: [] });
        } else if (rule.action === "confirm" || rule.action === "watch") {
          c.add({ rule: rule.action === "confirm" ? "tool.confirmed" : "tool.watched", verdict: "watch", message: rule.action === "confirm" ? `${tool.name} confirmed by the person` : `${tool.name} allowed and recorded`, owasp: ["LLM06"], atlas: [] });
        }
      }
      const argText = JSON.stringify(args);
      scanData(c, argText, policy, policy.pii.toolCall, policy.secrets.toolCall, `The arguments to ${tool.name}`, true);
      // A tool call can't be masked half-way: masking turns into blocking.
      for (const f of c.findings) if (f.verdict === "redact") f.verdict = "block";
      c.masks = [];
      break;
    }
    case "retrieval": {
      const roles = new Set((req.user?.roles ?? []).map((r) => r.toLowerCase()));
      const kept: Array<{ id: string; text: string }> = [];
      withheld = [];
      for (const doc of req.documents ?? []) {
        const access = (doc.access ?? []).map((a) => a.toLowerCase());
        if (policy.retrieval.enforceAccess && access.length && !access.some((a) => roles.has(a))) {
          withheld.push(doc.id);
          c.add({ rule: "retrieval.access", verdict: "redact", message: `Document ${doc.id} is for ${access.slice(0, 3).join(", ")}; withheld from this person`, owasp: ["LLM08"], atlas: [] });
          continue;
        }
        const docCollector = new Collector();
        scanInjection(docCollector, doc.text, policy.injection.retrieval, "content", `Document ${doc.id}`);
        if (docCollector.decision === "block") {
          withheld.push(doc.id);
          for (const f of docCollector.findings) c.add({ ...f, verdict: "redact", message: `${f.message}; withheld` });
          continue;
        }
        for (const f of docCollector.findings) c.add(f);
        scanData(docCollector, doc.text, policy, policy.pii.retrieval, policy.secrets.toolOutput, `Document ${doc.id}`, false);
        for (const f of docCollector.findings.filter((f) => f.rule === "secret" || f.rule.startsWith("pii."))) c.add(f.verdict === "block" ? { ...f, verdict: "redact", message: `${f.message}; withheld` } : f);
        if (docCollector.findings.some((f) => (f.rule === "secret" || f.rule.startsWith("pii.")) && f.verdict === "block")) {
          withheld.push(doc.id);
          continue;
        }
        kept.push({ id: doc.id, text: docCollector.masks.length ? redact(doc.text, docCollector.masks) : doc.text });
      }
      documents = kept;
      break;
    }
  }

  const decision = c.decision;
  const enforced: Verdict = ctx.mode === "monitor" ? (decision === "allow" ? "allow" : "watch") : decision;
  const masked = decision === "redact" && c.masks.length ? redact(text, c.masks) : undefined;
  const findings = c.findings.sort((a, b) => VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict]);
  return {
    decision,
    enforced,
    findings,
    ...(masked !== undefined && ctx.mode === "enforce" ? { content: masked } : {}),
    ...(documents ? { documents: ctx.mode === "enforce" ? documents : (req.documents ?? []).map((d) => ({ id: d.id, text: d.text })), withheld: ctx.mode === "enforce" ? withheld : [] } : {}),
    ...(needsConfirmation && ctx.mode === "enforce" ? { needsConfirmation } : {}),
    explanation: explain(decision, enforced, findings, req.stage),
  };
}

const VERB: Record<Verdict, string> = { allow: "Allowed", watch: "Allowed and recorded", redact: "Allowed with masking", block: "Blocked" };

export function explain(decision: Verdict, enforced: Verdict, findings: GuardFinding[], stage: Stage): string {
  if (!findings.length) return `Allowed: nothing in the ${stage.replace("_", " ")} matched this system's policy.`;
  const top = findings.slice(0, 3).map((f) => `${f.message}${f.owasp.length ? ` (OWASP ${f.owasp.join(", ")})` : ""}`);
  const lead = decision === enforced ? VERB[decision] : `Monitor mode: would have been ${VERB[decision].toLowerCase()}; ${enforced === "allow" ? "allowed" : "allowed and recorded"}`;
  return `${lead}. ${top.join(". ")}${findings.length > 3 ? `. And ${findings.length - 3} more.` : "."}`;
}

// The OWASP categories a policy enforces (block or mask) for posture.
export function guardedCategories(policy: GuardPolicy, mode: "enforce" | "monitor"): string[] {
  if (mode !== "enforce") return [];
  const on = (a: string) => a === "block" || a === "redact";
  const out: string[] = [];
  if (on(policy.injection.prompt) && on(policy.injection.retrieval) && on(policy.injection.toolOutput) && on(policy.jailbreak)) out.push("LLM01");
  if (on(policy.secrets.output) && on(policy.pii.output) && policy.pii.kinds.length) out.push("LLM02");
  if (on(policy.output.activeContent)) out.push("LLM05");
  if (policy.tools.default === "block") out.push("LLM06");
  if (on(policy.canary) && on(policy.promptExtraction)) out.push("LLM07");
  if (policy.retrieval.enforceAccess && on(policy.injection.retrieval)) out.push("LLM08");
  if (policy.limits.maxInputChars <= 50_000) out.push("LLM10");
  return out;
}
