import type { AgentKey } from "@/lib/ai/catalog";
import type { CaseEvidence } from "@/lib/ai/evidence";
import { renderEvidence } from "@/lib/ai/evidence";
import type { LlmProvider, LlmUsage } from "@/lib/ai/provider";
import type { AgentProfileView } from "@/lib/ai/resolve";
import { TriageSchema, builtinTriage, groundTriage, normalizeTriage, type GroundingReport, type TriageOutput } from "@/lib/ai/triage";
import { UNTRUSTED_RULES, holdDowngrades, scanForInjection, type InjectionFinding } from "@/lib/ai/safety";

// Case-level agents: the triage first responder and its specialist variants
// (phishing analyst, threat-intel enricher) share one output contract; the
// report writer produces client-facing Markdown. Every agent falls back to
// the built-in engine when no model is configured or the model call fails.

const SOC_CONTEXT =
  "You work inside a managed security operations center (MSSP/MDR) that protects client organizations. The case data below was collected by the SOC from the client's own security tools for defensive incident response. Base every statement on the supplied evidence and never invent hosts, accounts, IPs, hashes, or timestamps.";

const TRIAGE_RULES = `${UNTRUSTED_RULES}

Rules:
- Cite evidence ids (D1, E4, I2, T3, C1) for every key finding. A finding you can't cite doesn't belong in the output.
- Recommend containment only against targets listed in <entities>, spelled exactly as they appear there. Prefer the least disruptive action that stops the threat; recommend nothing when the evidence doesn't justify it.
- A human analyst does the primary analysis after you: be explicit about what you are unsure of in analyst_next_steps.
- confidence is 0-1 and reflects the evidence, not the severity. escalation_tier: 1 = routine triage, 2 = needs analyst investigation, 3 = active incident needing incident response.`;

const ROLE: Record<Extract<AgentKey, "triage" | "phishing" | "threat_intel">, string> = {
  triage:
    "Role: Tier-1 SOC first responder. Perform the initial analysis of a newly opened case: decide whether it is a true positive, how severe it is, what the key evidence is, and which containment steps should happen now, then hand it to the right analyst tier.",
  phishing:
    "Role: email-security specialist. Analyze the reported message: is the sender who they claim to be, what is the lure, what does the payload (link or attachment) do, and what should be blocked or purged. Treat a forensic module verdict as one input, not the answer.",
  threat_intel:
    "Role: threat-intelligence analyst. Assess the case's indicators: reputation, infrastructure shared with related cases, plausible campaign or actor tradecraft, and which indicators are worth blocking. Only recommend blocking indicators that are malicious or clearly attacker-controlled.",
};

function instructions(profile: AgentProfileView) {
  return profile.instructions?.trim() ? `\n\nAdditional instructions from this SOC:\n${profile.instructions.trim()}` : "";
}

export interface AgentOutcome<T> {
  output: T;
  engine: string;
  model: string | null;
  isLocal: boolean;
  usage: LlmUsage;
  status: "succeeded" | "fallback";
  error?: string;
  durationMs: number;
}

export async function runTriageAgent(
  key: "triage" | "phishing" | "threat_intel",
  evidence: CaseEvidence,
  profile: AgentProfileView,
  provider: LlmProvider | null,
): Promise<AgentOutcome<TriageOutput>> {
  const started = Date.now();
  if (provider) {
    try {
      const res = await provider.structured({
        schema: TriageSchema,
        schemaName: "case_triage",
        system: `${SOC_CONTEXT}\n\n${ROLE[key]}\n\n${TRIAGE_RULES}${instructions(profile)}`,
        user: renderEvidence(evidence),
        effort: profile.effort,
      });
      return { output: normalizeTriage(res.data), engine: provider.name, model: res.model, isLocal: provider.isLocal, usage: res.usage, status: "succeeded", durationMs: Date.now() - started };
    } catch (err) {
      return {
        output: builtinTriage(evidence),
        engine: "built-in",
        model: null,
        isLocal: true,
        usage: {},
        status: "fallback",
        error: `${provider.name}: ${err instanceof Error ? err.message : String(err)}`,
        durationMs: Date.now() - started,
      };
    }
  }
  return { output: builtinTriage(evidence), engine: "built-in", model: null, isLocal: true, usage: {}, status: "succeeded", durationMs: Date.now() - started };
}

export interface ReportContext {
  triage?: TriageOutput | null;
  actions: Array<{ label: string; target: string | null; status: string; manual?: boolean }>;
}

export function builtinReport(evidence: CaseEvidence, ctx: ReportContext): string {
  const t = ctx.triage;
  const done = ctx.actions.filter((a) => a.status === "EXECUTED");
  const pending = ctx.actions.filter((a) => a.status === "PENDING_APPROVAL");
  const byHand = ctx.actions.filter((a) => a.status === "MANUAL_REQUIRED");
  const lines = [
    `# Incident summary: ${evidence.title}`,
    "",
    `**Client:** ${evidence.tenantName ?? "Internal"} · **Severity:** ${evidence.severity.toLowerCase()} · **Status:** ${evidence.status.toLowerCase().replaceAll("_", " ")}`,
    "",
    "## What happened",
    t?.summary.replace(/ Built-in analysis — no language model was used\.$/, "") ?? evidence.summary ?? "Our monitoring flagged activity that is under review.",
    "",
    "## What we have done",
    done.length ? done.map((a) => `- ${a.label}${a.target ? ` — ${a.target}` : ""}${a.manual ? " (carried out by hand by our analyst)" : ""}`).join("\n") : "- Investigation is in progress; no containment has been needed yet.",
  ];
  if (pending.length) {
    lines.push("", "## Waiting on approval", pending.map((a) => `- ${a.label}${a.target ? ` — ${a.target}` : ""}`).join("\n"));
  }
  if (byHand.length) {
    lines.push("", "## Being carried out by our analysts", byHand.map((a) => `- ${a.label}${a.target ? ` — ${a.target}` : ""} (not yet confirmed done)`).join("\n"));
  }
  lines.push(
    "",
    "## What we recommend you do",
    ...(evidence.entities.users.length ? [`- Confirm with ${evidence.entities.users.slice(0, 2).join(", ")} whether the activity was theirs.`] : []),
    "- Reply to this case if any of the affected systems are business-critical, so we can coordinate containment.",
    "",
    "_Draft generated by HELIOS from the case evidence. Reviewed by your SOC analyst before publishing._",
  );
  return lines.join("\n");
}

export async function runReportAgent(
  evidence: CaseEvidence,
  ctx: ReportContext,
  profile: AgentProfileView,
  provider: LlmProvider | null,
): Promise<AgentOutcome<string>> {
  const started = Date.now();
  if (provider) {
    try {
      const res = await provider.text({
        system: `${SOC_CONTEXT}\n\n${UNTRUSTED_RULES}\n\nRole: client communications lead at the SOC. Write a short incident summary for the client's management in GitHub-flavored Markdown with these sections: What happened; What we have done; What we recommend you do; Current status. Plain language, no internal jargon or evidence ids, no speculation beyond the evidence. Mention any containment step still waiting to be carried out by hand (status MANUAL_REQUIRED) as an open action. Start with a level-1 heading. Output only the report.${instructions(profile)}`,
        user: `${renderEvidence(evidence)}\n\n<first_response>\n${JSON.stringify({ triage: ctx.triage ?? null, actions: ctx.actions }, null, 2)}\n</first_response>`,
        effort: profile.effort,
      });
      return { output: res.data, engine: provider.name, model: res.model, isLocal: provider.isLocal, usage: res.usage, status: "succeeded", durationMs: Date.now() - started };
    } catch (err) {
      return { output: builtinReport(evidence, ctx), engine: "built-in", model: null, isLocal: true, usage: {}, status: "fallback", error: `${provider.name}: ${err instanceof Error ? err.message : String(err)}`, durationMs: Date.now() - started };
    }
  }
  return { output: builtinReport(evidence, ctx), engine: "built-in", model: null, isLocal: true, usage: {}, status: "succeeded", durationMs: Date.now() - started };
}

export interface CaseAnalysis {
  outcome: AgentOutcome<TriageOutput>;
  output: TriageOutput;
  report: GroundingReport & { injection: InjectionFinding[]; held: boolean };
  manipulated: boolean;
}

// The one triage pipeline, used by first response and by evaluations alike:
// scan the evidence for text aimed at the AI, run the agent on escaped
// evidence, keep only what the evidence supports, then hold any downgrade
// the evidence doesn't justify for a human.
export async function analyzeCase(
  key: "triage" | "phishing" | "threat_intel",
  evidence: CaseEvidence,
  profile: AgentProfileView,
  provider: LlmProvider | null,
): Promise<CaseAnalysis> {
  const injection = scanForInjection(evidence);
  const outcome = await runTriageAgent(key, evidence, profile, provider);
  const grounded = groundTriage(outcome.output, evidence);
  const held = holdDowngrades(grounded.output, evidence, injection);
  return {
    outcome,
    output: held.output,
    report: { ...grounded.report, notes: [...grounded.report.notes, ...held.notes], injection, held: held.held },
    manipulated: injection.length > 0,
  };
}
