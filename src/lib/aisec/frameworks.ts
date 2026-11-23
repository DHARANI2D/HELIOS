// The frameworks AI security is measured against, and what HELIOS does for
// each item: the OWASP Top 10 for LLM applications (2025), MITRE ATLAS
// techniques, and where HELIOS produces evidence for the NIST AI RMF,
// ISO/IEC 42001 and the EU AI Act. HELIOS provides evidence and controls
// for parts of these; it doesn't certify anyone against them. Pure.

export interface OwaspItem {
  id: string;
  name: string;
  what: string;
  test: string | null;
  guard: string | null;
  // Outside what HELIOS can see from the outside or at runtime.
  outside?: string;
}

export const OWASP_LLM: OwaspItem[] = [
  { id: "LLM01", name: "Prompt injection", what: "Input, typed or hidden in content the AI reads, that changes what it does.", test: "Direct, encoded, role-play and delimiter injections with a canary the AI must not repeat.", guard: "Injection and jailbreak checks on prompts, retrieved documents and tool results." },
  { id: "LLM02", name: "Sensitive information disclosure", what: "Personal data, credentials or confidential data in answers.", test: "Asks for other people's data and for credentials; flags any that appear.", guard: "Masks personal data and credentials in prompts, documents and answers." },
  { id: "LLM03", name: "Supply chain", what: "Compromised models, datasets, plugins or libraries.", test: null, guard: null, outside: "Covered by the AI system inventory (provider and model recorded) and the client's own software supply-chain controls." },
  { id: "LLM04", name: "Data and model poisoning", what: "Training or fine-tuning data manipulated to plant behaviour.", test: null, guard: null, outside: "Training happens outside HELIOS; poisoned documents at retrieval time are caught as indirect injection." },
  { id: "LLM05", name: "Improper output handling", what: "Answers passed to a browser, shell or database without checks.", test: "Asks for scripts, javascript: links and markup; flags any returned.", guard: "Blocks active content and checks links in answers." },
  { id: "LLM06", name: "Excessive agency", what: "An AI with more tools, permissions or autonomy than its task needs.", test: "Asks it to take actions nobody confirmed; flags answers that claim to have done so.", guard: "Tools denied by default, argument rules, confirmation for risky actions, tools limited to the declared task." },
  { id: "LLM07", name: "System prompt leakage", what: "The hidden instructions (and anything secret in them) coming out.", test: "Extraction attempts; a canary planted in the system prompt proves a leak.", guard: "Blocks extraction requests and any answer carrying the canary." },
  { id: "LLM08", name: "Vector and embedding weaknesses", what: "RAG stores that return documents the person may not see, or poisoned ones.", test: null, guard: "Retrieval check: documents filtered by the person's roles, instructions in them blocked." },
  { id: "LLM09", name: "Misinformation", what: "Confident answers that are false (hallucination).", test: "Asks about things that don't exist; flags confident made-up answers.", guard: null },
  { id: "LLM10", name: "Unbounded consumption", what: "Requests that run up cost or deny service.", test: "Oversized prompts and requests for enormous answers.", guard: "Prompt size cap and a per-system rate limit." },
];

export const ATLAS: Record<string, string> = {
  "AML.T0051.000": "LLM Prompt Injection: Direct",
  "AML.T0051.001": "LLM Prompt Injection: Indirect",
  "AML.T0054": "LLM Jailbreak",
  "AML.T0056": "LLM Meta Prompt Extraction",
  "AML.T0057": "LLM Data Leakage",
  "AML.T0053": "LLM Plugin Compromise",
  "AML.T0029": "Denial of ML Service",
};

export interface FrameworkItem {
  ref: string;
  title: string;
  evidence: string;
}

export const FRAMEWORKS: Record<string, { label: string; note: string; items: FrameworkItem[] }> = {
  nist: {
    label: "NIST AI RMF",
    note: "The four functions of the NIST AI Risk Management Framework (AI RMF 1.0).",
    items: [
      { ref: "GOVERN", title: "Policies, roles and accountability for AI risk", evidence: "Guard policies per AI system with version history (who changed what, and why); approvals for red-team tests by the client and HELIOS." },
      { ref: "MAP", title: "Context and risks of each AI system", evidence: "AI system inventory: purpose, owner, model, the data it handles, tools it may call." },
      { ref: "MEASURE", title: "Testing and monitoring", evidence: "AI red-team results by OWASP category with evidence; guard decisions per system over time." },
      { ref: "MANAGE", title: "Treating and responding to risk", evidence: "Recommended protections applied from findings; guard blocks; cases opened for leaks and sustained attacks, worked by the SOC." },
    ],
  },
  iso42001: {
    label: "ISO/IEC 42001",
    note: "Annex A control areas of ISO/IEC 42001:2023 (AI management system) where HELIOS records evidence.",
    items: [
      { ref: "A.2", title: "Policies related to AI", evidence: "Each AI system's guard policy and its history." },
      { ref: "A.5", title: "Assessing impacts of AI systems", evidence: "Red-team reports and the OWASP posture per system." },
      { ref: "A.6", title: "AI system life cycle", evidence: "Red team before release, guard at runtime, re-test after changes." },
      { ref: "A.7", title: "Data for AI systems", evidence: "Data classes per system; personal data masked before it reaches the model provider." },
      { ref: "A.9", title: "Use of AI systems", evidence: "Signed receipts for every guard decision; monitored use with cases on misuse." },
      { ref: "A.10", title: "Third-party and customer relationships", evidence: "Model provider per system; the gateway keeps provider keys out of applications." },
    ],
  },
  euai: {
    label: "EU AI Act",
    note: "Requirements for high-risk AI systems where HELIOS records evidence. Whether a system is high-risk is the client's assessment.",
    items: [
      { ref: "Art. 9", title: "Risk management system", evidence: "Red-team findings, accepted risks with reasons, re-tests." },
      { ref: "Art. 10", title: "Data and data governance", evidence: "Data classes per system and masking of personal data." },
      { ref: "Art. 12", title: "Record-keeping", evidence: "Every guard decision logged with a signed receipt; optional sealed transcripts." },
      { ref: "Art. 14", title: "Human oversight", evidence: "Risky tool actions held for a person's confirmation; the SOC reviews cases the guard opens." },
      { ref: "Art. 15", title: "Accuracy, robustness and cybersecurity", evidence: "Red-team results against injection, leakage and misuse; runtime guard." },
    ],
  },
};

// ---------------------------------------------------------------- posture

export type PostureState = "protected" | "tested" | "gap" | "partial" | "outside";

export interface PostureRow {
  id: string;
  name: string;
  state: PostureState;
  detail: string;
}

export interface PostureInput {
  systems: number;
  // Systems whose policy enforces the control for this category.
  guarded: Record<string, number>;
  // Red team: tested systems and open findings per category.
  tested: Record<string, number>;
  open: Record<string, number>;
}

export function postureOf(input: PostureInput): { rows: PostureRow[]; score: number } {
  const rows = OWASP_LLM.map<PostureRow>((o) => {
    const open = input.open[o.id] ?? 0;
    const tested = input.tested[o.id] ?? 0;
    const guarded = input.guarded[o.id] ?? 0;
    if (!input.systems) return { id: o.id, name: o.name, state: "gap", detail: "No AI systems registered yet" };
    if (open > 0) return { id: o.id, name: o.name, state: "gap", detail: `${open} open red-team finding(s)` };
    if (!o.test && !o.guard) return { id: o.id, name: o.name, state: "outside", detail: o.outside ?? "Outside what HELIOS checks" };
    if (o.guard && guarded >= input.systems) return { id: o.id, name: o.name, state: "protected", detail: `Guarded on all ${input.systems} system(s)${tested ? `; red team passed on ${tested}` : ""}` };
    if (tested && (!o.guard || guarded > 0)) return { id: o.id, name: o.name, state: "tested", detail: `Red team passed on ${tested} system(s)${o.guard ? `; guarded on ${guarded} of ${input.systems}` : ""}` };
    if (guarded > 0) return { id: o.id, name: o.name, state: "partial", detail: `Guarded on ${guarded} of ${input.systems} system(s)` };
    return { id: o.id, name: o.name, state: "gap", detail: o.guard ? "Not guarded or tested yet" : "Not tested yet" };
  });
  const weight: Record<PostureState, number | null> = { protected: 1, tested: 0.75, partial: 0.5, gap: 0, outside: null };
  const counted = rows.filter((r) => weight[r.state] != null);
  const score = counted.length ? Math.round((counted.reduce((s, r) => s + (weight[r.state] ?? 0), 0) / counted.length) * 100) : 0;
  return { rows, score };
}
