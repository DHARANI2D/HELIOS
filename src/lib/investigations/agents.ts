import Anthropic from "@anthropic-ai/sdk";
import { betaZodOutputFormat } from "@anthropic-ai/sdk/helpers/beta/zod";
import { z } from "zod";

import type { UesEvent } from "@/lib/investigations/normalize";
import type { EntityGraph } from "@/lib/investigations/graph";
import {
  hhmmss,
  type Finding,
  type PriorCase,
  type QaResult,
  type RcaResult,
  type TriageResult,
} from "@/lib/investigations/heuristics";

// Port of asip's LangGraph swarm (agents/{triage,rca,qa,report}_agent.py +
// orchestrator.py) onto the Claude API. The orchestration is plain code — the
// graph is a fixed triage → rca → qa ⇄ rca → report loop, so a framework
// would add a dependency without adding control flow.

const MODEL = process.env.ANTHROPIC_MODEL ?? "claude-opus-5-5";
// Evidence beyond this is summarized by the detector findings rather than
// sent verbatim; the prompt says so explicitly.
const MAX_EVENTS_IN_PROMPT = 300;

export function claudeConfigured(): boolean {
  const forced = process.env.INVESTIGATIONS_ENGINE;
  if (forced === "heuristic") return false;
  if (forced === "claude") return true;
  return !!(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}

export class AgentRefusalError extends Error {}

let client: Anthropic | null = null;
function anthropic() {
  client ??= new Anthropic();
  return client;
}

const TriageSchema = z.object({
  alert_type: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  mitre_tactic: z.string(),
  initial_hypothesis: z.string(),
  evidence_required: z.array(z.string()),
});

const RcaSchema = z.object({
  root_cause: z.string(),
  timeline: z.array(z.string()),
  confidence_score: z.number(),
  mitre_techniques: z.array(z.object({ id: z.string(), name: z.string(), evidence: z.string() })),
});

const QaSchema = z.object({
  is_valid: z.boolean(),
  validated_evidence: z.array(z.string()),
  issues: z.array(z.string()),
});

function requestBase() {
  return {
    model: MODEL,
    max_tokens: 16000,
    // Investigation telemetry is attack activity by definition; route any
    // safety-classifier decline to Anthropic's recommended fallback model
    // instead of failing the stage.
    betas: ["server-side-fallback-2026-07-01"] as Anthropic.Beta.AnthropicBeta[],
    fallbacks: "default" as const,
  };
}

async function structured<S extends z.ZodType>(
  schema: S,
  system: string,
  user: string,
  effort: "low" | "medium" | "high",
): Promise<z.infer<S>> {
  const response = await anthropic().beta.messages.parse({
    ...requestBase(),
    output_config: { effort, format: betaZodOutputFormat(schema) },
    system,
    messages: [{ role: "user", content: user }],
  });
  if (response.stop_reason === "refusal") {
    throw new AgentRefusalError(`Model declined the request (${response.stop_details?.category ?? "unspecified"})`);
  }
  if (!response.parsed_output) throw new Error(`No structured output (stop_reason: ${response.stop_reason})`);
  return response.parsed_output as z.infer<S>;
}

// --- evidence formatting ---------------------------------------------------

function compactEvent(e: UesEvent) {
  return {
    t: e.timestamp.toISOString(),
    type: e.eventType,
    host: e.hostName,
    user: e.userName,
    proc: e.processName,
    pid: e.processPid,
    parent: e.parentProcessName,
    ppid: e.parentProcessPid,
    cmd: e.commandLine,
    dst: e.dstIp ? `${e.dstIp}${e.dstPort ? `:${e.dstPort}` : ""}` : undefined,
    file: e.filePath,
    sha256: e.fileHash,
    query: e.query,
  };
}

export function buildEvidence(events: UesEvent[], findings: Finding[], graph: EntityGraph) {
  const flagged = new Set(findings.flatMap((f) => f.events));
  const ordered = [...events].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  let shown = ordered;
  let note = `All ${events.length} normalized events are included.`;
  if (events.length > MAX_EVENTS_IN_PROMPT) {
    const rest = ordered.filter((e) => !flagged.has(e)).slice(0, Math.max(0, MAX_EVENTS_IN_PROMPT - flagged.size));
    shown = [...flagged, ...rest].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    note = `${shown.length} of ${events.length} events are included: every event cited by a detector finding, then the earliest remaining events. The detector findings summarize the full set.`;
  }

  const labels = new Map(graph.nodes.map((n) => [n.id, `${n.label}${n.pid !== undefined ? `(${n.pid})` : ""}`]));
  const edges = graph.edges.slice(0, 250).map((e) => `${labels.get(e.source)} -${e.relation}-> ${labels.get(e.target)}`);

  const findingsText = findings.length
    ? findings
        .map((f) => `- [${f.severity}] ${f.title} (${f.techniques.join(", ")}): ${f.description} Events at ${f.events.slice(0, 5).map((e) => hhmmss(e.timestamp)).join(", ")}`)
        .join("\n")
    : "- No deterministic rule matched.";

  return [
    `<detector_findings>\n${findingsText}\n</detector_findings>`,
    `<process_graph edges="${graph.edges.length}">\n${edges.join("\n")}\n</process_graph>`,
    `<events note="${note}">\n${shown.map((e) => JSON.stringify(compactEvent(e))).join("\n")}\n</events>`,
  ].join("\n\n");
}

// --- agents ----------------------------------------------------------------

const ANALYST_CONTEXT =
  "You are part of a security operations investigation pipeline. The telemetry below was collected from the organization's own endpoints by its SOC for defensive incident response. Base every statement on the supplied events; never invent hosts, PIDs, IPs, or timestamps.";

export async function triageAgent(title: string, details: string, evidence: string): Promise<TriageResult> {
  return structured(
    TriageSchema,
    `${ANALYST_CONTEXT}\nRole: Tier-3 SOC analyst performing triage. Classify the alert, assess severity, name the most relevant ATT&CK tactic, state an initial hypothesis about how the activity happened (including likely parent/child processes), and list the telemetry needed to confirm it.`,
    `<alert title="${title.replaceAll('"', "'")}">\n${details || "(no analyst notes)"}\n</alert>\n\n${evidence}`,
    "medium",
  );
}

export async function rcaAgent(triage: TriageResult, evidence: string, qaFeedback?: string[], prior: PriorCase[] = []): Promise<RcaResult> {
  return structured(
    RcaSchema,
    `${ANALYST_CONTEXT}\nRole: lead incident responder producing a root cause analysis. Connect the process graph and events chronologically to explain the attack path from entry point to impact. Timeline entries must be formatted "HH:MM:SS - description" using UTC times copied exactly from the events, and should cite PIDs, process names, and destinations. confidence_score is 0-1. Map each ATT&CK technique you assert to the evidence supporting it, using technique IDs such as T1059.001.`,
    `<triage>\n${JSON.stringify(triage, null, 2)}\n</triage>\n\n${evidence}${
      prior.length
        ? `\n\n<related_cases note="Earlier HELIOS cases that share hosts, accounts, or indicators with this one. Use them as context (recurrence, campaign links); they are not evidence for this incident's timeline.">\n${JSON.stringify(prior, null, 2)}\n</related_cases>`
        : ""
    }${
      qaFeedback?.length ? `\n\n<qa_feedback>\nThe previous RCA failed validation. Correct these problems:\n${qaFeedback.map((i) => `- ${i}`).join("\n")}\n</qa_feedback>` : ""
    }`,
    "high",
  );
}

export async function qaAgent(rca: RcaResult, evidence: string): Promise<QaResult> {
  return structured(
    QaSchema,
    `${ANALYST_CONTEXT}\nRole: adversarial QA validator. Try to falsify the RCA: every claim in root_cause and timeline must match a specific event (timestamp, process, PID, destination), and the sequence must be causally possible (e.g. a process cannot connect out before it was created). List confirmed claims in validated_evidence and every discrepancy in issues. is_valid is true only if there are no material issues.`,
    `<rca>\n${JSON.stringify(rca, null, 2)}\n</rca>\n\n${evidence}`,
    "medium",
  );
}

export async function reportAgent(title: string, triage: TriageResult, rca: RcaResult, qa: QaResult): Promise<string> {
  const response = await anthropic().beta.messages.create({
    ...requestBase(),
    output_config: { effort: "medium" },
    system: `${ANALYST_CONTEXT}\nRole: principal security consultant. Write a formal SOC incident report in GitHub-flavored Markdown with these sections: Executive summary; Root cause analysis & timeline; MITRE ATT&CK mapping (table); Containment & mitigation (Immediate / Short-term / Long-term); Evidence verification (summarize the QA result honestly, including unresolved issues). Start with a level-1 heading. Output only the report.`,
    messages: [
      {
        role: "user",
        content: `<incident title="${title.replaceAll('"', "'")}" />\n<triage>\n${JSON.stringify(triage, null, 2)}\n</triage>\n<rca>\n${JSON.stringify(rca, null, 2)}\n</rca>\n<qa>\n${JSON.stringify(qa, null, 2)}\n</qa>`,
      },
    ],
  });
  if (response.stop_reason === "refusal") {
    throw new AgentRefusalError(`Model declined the report (${response.stop_details?.category ?? "unspecified"})`);
  }
  const text = response.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n").trim();
  if (!text) throw new Error(`Empty report (stop_reason: ${response.stop_reason})`);
  return text;
}

export { MODEL as INVESTIGATION_MODEL };
