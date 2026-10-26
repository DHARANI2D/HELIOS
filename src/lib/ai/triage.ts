import { z } from "zod";
import type { CaseSeverity, DetectionSource, PlaybookActionType } from "@prisma/client";

import type { CaseEntities, CaseEvidence } from "@/lib/ai/evidence";

// The first-responder contract: what a triage agent (Claude, a local model,
// or the built-in engine) must return about a case, plus the grounding check
// that decides how much of it to trust. Pure — no I/O.

export const PROPOSABLE_ACTIONS = [
  "ISOLATE_HOST",
  "BLOCK_IP",
  "DISABLE_USER",
  "KILL_PROCESS",
  "QUARANTINE_FILE",
  "BLOCK_SENDER",
  "COLLECT_LOGS",
  "REVOKE_AGENT",
] as const satisfies readonly PlaybookActionType[];

export const TriageSchema = z.object({
  verdict: z.enum(["true_positive", "suspicious", "benign", "needs_investigation"]),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.number().describe("0 to 1: how sure you are of the verdict given the evidence"),
  summary: z.string().describe("Initial analysis in 2-4 sentences for the analyst taking over"),
  key_findings: z
    .array(z.object({ finding: z.string(), evidence: z.array(z.string()).describe("Evidence ids such as D1, E4, I2") }))
    .describe("Each finding must cite the evidence ids it rests on"),
  recommended_actions: z.array(
    z.object({
      action: z.enum(PROPOSABLE_ACTIONS),
      target: z.string().describe("Exact host, IP, account, process, SHA-256, sender address or agent id from the evidence"),
      rationale: z.string(),
      urgency: z.enum(["immediate", "soon", "optional"]),
    }),
  ),
  analyst_next_steps: z.array(z.string()).describe("What the human analyst should verify first"),
  escalation_tier: z.number().int().describe("1 = triage, 2 = analyst investigation, 3 = incident response"),
});

export type TriageOutput = z.infer<typeof TriageSchema>;
export type ProposedAction = TriageOutput["recommended_actions"][number];

export const SEVERITY_FROM_AI: Record<TriageOutput["severity"], CaseSeverity> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function normalizeTriage(out: TriageOutput): TriageOutput {
  return {
    ...out,
    confidence: Math.min(1, Math.max(0, Number.isFinite(out.confidence) ? out.confidence : 0.5)),
    escalation_tier: Math.min(3, Math.max(1, Math.round(out.escalation_tier || 1))),
    key_findings: out.key_findings.slice(0, 12),
    recommended_actions: out.recommended_actions.slice(0, 10),
    analyst_next_steps: out.analyst_next_steps.slice(0, 8),
  };
}

// --- grounding --------------------------------------------------------------

export interface ActionGrounding {
  action: PlaybookActionType;
  target: string;
  grounded: boolean;
  // The evidence value the target matched (canonical spelling for execution).
  matched?: string;
}

export interface GroundingReport {
  findingsTotal: number;
  findingsGrounded: number;
  invalidRefs: string[];
  actions: ActionGrounding[];
  confidenceBefore: number;
  confidenceAfter: number;
  notes: string[];
}

const norm = (s: string) => s.trim().toLowerCase();
const shortHost = (h: string) => norm(h).split(".")[0];
const shortUser = (u: string) => norm(u).replace(/^.*\\/, "").replace(/@.*$/, "");

function matchIn(values: string[], target: string, keys: Array<(s: string) => string>): string | undefined {
  for (const key of keys) {
    const t = key(target);
    if (!t) continue;
    const hit = values.find((v) => key(v) === t);
    if (hit) return hit;
  }
  return undefined;
}

export function matchTarget(action: PlaybookActionType, target: string, e: CaseEntities): string | undefined {
  switch (action) {
    case "ISOLATE_HOST":
    case "RELEASE_HOST":
    case "COLLECT_LOGS":
      return matchIn(e.hosts, target, [norm, shortHost]);
    case "BLOCK_IP":
    case "UNBLOCK_IP":
      return matchIn(e.ips, target, [norm]);
    case "DISABLE_USER":
    case "ENABLE_USER":
      return matchIn(e.users, target, [norm, shortUser]);
    case "KILL_PROCESS":
      return matchIn(e.processes, target.split(/[\\/:]/).pop() ?? target, [norm]);
    case "QUARANTINE_FILE":
      return matchIn(e.hashes, target, [norm]);
    case "BLOCK_SENDER":
      return matchIn([...e.emails, ...e.domains], target, [norm]);
    case "REVOKE_AGENT":
    case "RESTORE_AGENT":
      return matchIn(e.agents, target, [norm]);
    default:
      return undefined;
  }
}

// Findings must cite real evidence ids; action targets must be entities that
// actually appear in the case. Ungrounded findings are dropped and confidence
// is discounted in proportion; ungrounded actions are kept but marked, and
// the response policy blocks them.
export function groundTriage(output: TriageOutput, evidence: Pick<CaseEvidence, "refs" | "entities">): { output: TriageOutput; report: GroundingReport } {
  const known = new Set(evidence.refs.map((r) => r.ref.toUpperCase()));
  const invalid = new Set<string>();
  const findings = output.key_findings.map((f) => {
    const cited = f.evidence.map((r) => r.trim().toUpperCase());
    const valid = cited.filter((r) => known.has(r));
    cited.filter((r) => !known.has(r)).forEach((r) => invalid.add(r));
    return { ...f, evidence: valid };
  });
  const grounded = findings.filter((f) => f.evidence.length > 0);

  const actions: ActionGrounding[] = output.recommended_actions.map((a) => {
    const matched = matchTarget(a.action, a.target, evidence.entities);
    return { action: a.action, target: a.target, grounded: !!matched, matched };
  });

  const notes: string[] = [];
  let confidence = output.confidence;
  if (findings.length === 0) {
    confidence = Math.min(confidence, 0.5);
    notes.push("No findings cited — confidence capped at 50%");
  } else if (grounded.length < findings.length) {
    const ratio = grounded.length / findings.length;
    confidence = confidence * (0.5 + ratio / 2);
    notes.push(`${findings.length - grounded.length} of ${findings.length} findings cited no valid evidence and were dropped`);
  }
  if (invalid.size) notes.push(`Unknown evidence ids: ${[...invalid].slice(0, 8).join(", ")}`);
  const blocked = actions.filter((a) => !a.grounded);
  if (blocked.length) notes.push(`${blocked.length} recommended action target(s) not found in the case evidence`);

  return {
    output: { ...output, key_findings: grounded, confidence },
    report: {
      findingsTotal: findings.length,
      findingsGrounded: grounded.length,
      invalidRefs: [...invalid],
      actions,
      confidenceBefore: output.confidence,
      confidenceAfter: confidence,
      notes,
    },
  };
}

// --- built-in deterministic first responder ---------------------------------

const HOST_SOURCES: DetectionSource[] = ["LATERAL_MOVEMENT", "PERSISTENCE", "DEFENSE_EVASION", "IMPACT", "FSM_CHAIN", "ANOMALOUS_ACTION"];
const IDENTITY_SOURCES: DetectionSource[] = ["CREDENTIAL_HARVESTING", "GEO_VELOCITY"];
const NETWORK_SOURCES: DetectionSource[] = ["THREAT_INTEL_MATCH", "DATA_EXFILTRATION", "RECONNAISSANCE"];
const SEVERITY_RANK: Record<CaseSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function maliciousIps(ev: CaseEvidence): string[] {
  const flagged = ev.refs
    .filter((r) => r.kind === "indicator" && r.text.startsWith("IP "))
    .filter((r) => {
      const m = r.text.match(/reputation=([\d.]+)/);
      return m ? Number(m[1]) >= 0.4 : false;
    })
    .map((r) => r.text.split(" ")[1]);
  return flagged.length ? flagged : [];
}

// Works with no model at all — offline deployments and the fallback when a
// model call fails. Conservative: it recommends, cites the detections it
// leaned on, and never claims more confidence than the detectors did.
export function builtinTriage(ev: CaseEvidence): TriageOutput {
  const detections = ev.refs.filter((r) => r.kind === "detection");
  const highDetections = detections.filter((r) => /^\[(HIGH|CRITICAL)\]/.test(r.text));
  const sources = new Set(ev.detectionSources);
  const moduleVerdict = (ev.verdict ?? "").toLowerCase();

  let verdict: TriageOutput["verdict"] = "needs_investigation";
  if (moduleVerdict === "malicious" || ev.maliciousIndicators > 0 || highDetections.length > 0) verdict = "true_positive";
  else if (moduleVerdict === "suspicious" || detections.length > 0) verdict = "suspicious";
  else if (moduleVerdict === "benign" || moduleVerdict === "clean") verdict = "benign";

  const base = ev.confidence ?? (verdict === "true_positive" ? 0.75 : verdict === "suspicious" ? 0.6 : 0.5);
  const confidence = Math.min(0.9, base);

  const actions: ProposedAction[] = [];
  const add = (action: ProposedAction["action"], target: string | undefined, rationale: string, urgency: ProposedAction["urgency"]) => {
    if (!target || actions.some((a) => a.action === action && a.target === target)) return;
    actions.push({ action, target, rationale, urgency });
  };
  const severe = SEVERITY_RANK[ev.severity] >= SEVERITY_RANK.HIGH;

  // A severe alert raised by the client's own EDR / identity provider is
  // already a vendor verdict on that host or account.
  const vendorEndpoint = sources.has("VENDOR_ALERT") && severe && ev.domain === "ENDPOINT";
  const vendorIdentity = sources.has("VENDOR_ALERT") && severe && ev.domain === "IDENTITY";

  // When the originating module judged the activity benign and nothing
  // high-severity fired (an approved change, a known scanner), it stays a
  // question for the analyst rather than a containment proposal.
  const vouched = (moduleVerdict === "benign" || moduleVerdict === "clean") && highDetections.length === 0;
  if ((verdict === "true_positive" || verdict === "suspicious") && !vouched) {
    if ([...sources].some((s) => HOST_SOURCES.includes(s)) || vendorEndpoint || (ev.sourceType === "SOC_INVESTIGATION" && verdict === "true_positive")) {
      for (const host of ev.entities.hosts.slice(0, 2)) add("ISOLATE_HOST", host, "Host shows post-exploitation behavior (persistence, lateral movement or impact)", severe ? "immediate" : "soon");
    }
    if ([...sources].some((s) => IDENTITY_SOURCES.includes(s)) || vendorIdentity) {
      for (const user of ev.entities.users.slice(0, 2)) add("DISABLE_USER", user, "Account shows credential-attack or impossible-travel activity", severe ? "immediate" : "soon");
    }
    if ([...sources].some((s) => NETWORK_SOURCES.includes(s)) || ev.maliciousIndicators > 0) {
      for (const ip of maliciousIps(ev).slice(0, 5)) add("BLOCK_IP", ip, "IP has a malicious reputation and appears in this case", "immediate");
    }
    if (ev.sourceType === "EMAIL_ANALYSIS" && verdict === "true_positive") {
      const sender = ev.refs.find((r) => r.kind === "indicator" && r.text.includes("role=sender"))?.text.split(" ")[1];
      add("BLOCK_SENDER", sender ?? ev.entities.emails[0], "Sender delivered a malicious message", "immediate");
      for (const hash of ev.entities.hashes.slice(0, 3)) add("QUARANTINE_FILE", hash, "Attachment flagged by forensic analysis", "immediate");
    }
    if (ev.sourceType === "AGENT_GOVERNANCE" && verdict === "true_positive") {
      add("REVOKE_AGENT", ev.entities.agents[0], "Governed AI agent violated policy", "immediate");
    }
    if (severe) for (const host of ev.entities.hosts.slice(0, 1)) add("COLLECT_LOGS", host, "Preserve surrounding telemetry before it ages out", "soon");
  }

  const topDetections = (highDetections.length ? highDetections : detections).slice(0, 4);
  const findings = topDetections.map((d) => ({ finding: d.text.replace(/^\[\w+\]\s*/, "").slice(0, 200), evidence: [d.ref] }));
  if (findings.length === 0) {
    const firstIndicator = ev.refs.find((r) => r.kind === "indicator");
    const firstEvent = ev.refs.find((r) => r.kind === "event" || r.kind === "timeline" || r.kind === "context");
    const ref = firstIndicator ?? firstEvent;
    if (ref) findings.push({ finding: ref.text.slice(0, 200), evidence: [ref.ref] });
  }

  const who = [ev.entities.hosts[0] && `host ${ev.entities.hosts[0]}`, ev.entities.users[0] && `account ${ev.entities.users[0]}`].filter(Boolean).join(" and ");
  const summary =
    verdict === "benign"
      ? `The originating module judged this ${ev.verdict ?? "benign"} and no detector fired with high severity. Recommend closing after a quick check.`
      : `${detections.length} detection${detections.length === 1 ? "" : "s"}${who ? ` involving ${who}` : ""}${ev.techniques.length ? ` map to ${ev.techniques.slice(0, 4).join(", ")}` : ""}. ${
          verdict === "true_positive" ? "The signals are consistent with real malicious activity" : "The activity is suspicious but not conclusive"
        }${ev.maliciousIndicators ? `, and ${ev.maliciousIndicators} linked indicator${ev.maliciousIndicators === 1 ? " has" : "s have"} a malicious reputation` : ""}. Built-in analysis — no language model was used.`;

  const tier = ev.severity === "CRITICAL" ? 3 : ev.severity === "HIGH" ? 2 : 1;
  const steps = [
    ev.entities.hosts[0] ? `Confirm with the endpoint owner whether the activity on ${ev.entities.hosts[0]} was expected` : null,
    ev.entities.users[0] ? `Review recent sign-ins for ${ev.entities.users[0]}` : null,
    ev.related.length ? `Compare with the related case "${ev.related[0].title}"` : null,
    "Validate the recommended containment before approving it",
  ].filter((s): s is string => !!s);

  return {
    verdict,
    severity: ev.severity.toLowerCase() as TriageOutput["severity"],
    confidence,
    summary,
    key_findings: findings,
    recommended_actions: actions,
    analyst_next_steps: steps,
    escalation_tier: tier,
  };
}
