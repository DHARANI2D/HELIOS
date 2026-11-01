import type { PlaybookActionType, ResponseAction } from "@prisma/client";

import { db } from "@/lib/db";
import { storedTriage } from "@/lib/ai/triage";
import { TECHNIQUES } from "@/lib/mitre/catalog";
import { ACTION_LABEL } from "@/lib/response/labels";
import { ROLLBACK_OF } from "@/lib/response/executor";
import { recordResponseAction } from "@/lib/response/service";
import type { EvidenceSweep } from "@/lib/ai/evidence-sweep";

// The final analysis HELIOS writes on its own once a case is contained and
// investigated: what happened, from which evidence, what is contained, when
// to lift it, and how to remediate. It's built from the investigation's
// cited findings and timeline, the containment on the case, the techniques
// and the evidence sweep; the report writer adds the narrative. People
// review it. Lifting containment and remediation steps are proposed as
// actions that wait for a person's approval: the AI never lifts containment
// or changes people's access on its own.

export interface ContainmentLine {
  action: string;
  target: string | null;
  status: string;
  by: "AI" | "person";
  at: string;
}

export interface LiftProposal {
  action: string;
  target: string | null;
  conditions: string[];
  // The release action waiting for approval, when HELIOS can do it.
  actionId: string | null;
  now: boolean;
}

export interface RemediationStep {
  step: string;
  why: string;
  owner: "SOC" | "Client IT" | "SOC or client";
  // An action waiting for approval, when HELIOS can carry the step out.
  actionId: string | null;
}

export interface FinalAnalysis {
  verdict: string;
  confidence: number;
  severity: string;
  summary: string;
  narrative: string | null;
  rootCause: string;
  scope: { hosts: string[]; users: string[]; ips: string[]; files: string[]; emails: string[] };
  timeline: Array<{ at: string; what: string; evidence: string[] }>;
  findings: Array<{ finding: string; evidence: string[] }>;
  techniques: Array<{ id: string; name: string; tactic: string }>;
  containment: ContainmentLine[];
  evidence: EvidenceSweep | null;
  lift: LiftProposal[];
  remediation: RemediationStep[];
  openQuestions: string[];
  basedOn: { agent: string; engine: string; model: string | null } | null;
}

const BENIGN = ["benign", "false_positive"];
const TACTIC = (id: string) => TECHNIQUES.find((t) => t.id === id || id.startsWith(`${t.id}.`))?.tactic ?? null;

// When contained things can be released again, per action.
function liftConditions(a: PlaybookActionType, target: string | null, tactics: Set<string>, benign: boolean): string[] {
  if (benign) return ["The investigation found this activity benign: lift it now unless the client says otherwise."];
  const t = target ?? "the target";
  switch (a) {
    case "ISOLATE_HOST":
      return [
        `A full scan of ${t} by the client's EDR comes back clean`,
        ...(tactics.has("TA0003") ? [`The persistence found on ${t} has been removed (or the device reimaged)`] : []),
        ...(tactics.has("TA0006") ? [`Passwords of accounts used on ${t} have been reset`] : []),
        `No new detections from ${t} for 24 hours while isolated`,
      ];
    case "BLOCK_IP":
      return [`${t} is no longer reported malicious by threat intelligence`, `No business system needs to reach ${t} (check with the client)`];
    case "DISABLE_USER":
      return [`The account's password is reset and its sessions revoked`, `MFA is re-registered by the owner in person or over a verified channel`];
    case "REVOKE_AGENT":
      return [`The agent's owner has reviewed what it did and rotated its credentials`];
    default:
      return [`The investigation's findings for ${t} are resolved`];
  }
}

const has = (tactics: Set<string>, ...ids: string[]) => ids.some((i) => tactics.has(i));

export async function buildFinalAnalysis(caseId: string, sweep: EvidenceSweep | null, narrative: string | null): Promise<FinalAnalysis> {
  const kase = await db.case.findUniqueOrThrow({
    where: { id: caseId },
    select: { id: true, title: true, severity: true, verdict: true, tenantId: true, mitreTechniques: { select: { techniqueId: true, technique: { select: { name: true } } } } },
  });
  const runs = await db.aiRun.findMany({ where: { caseId, agentKey: { in: ["investigator", "triage", "phishing", "threat_intel"] }, status: { not: "failed" } }, orderBy: { createdAt: "desc" } });
  const best = runs.find((r) => r.agentKey === "investigator") ?? runs[0] ?? null;
  const out = storedTriage(best?.output);
  const timeline = ((best?.output as { timeline?: FinalAnalysis["timeline"] } | null)?.timeline ?? []).slice(0, 40);
  const actions = await db.responseAction.findMany({ where: { caseId, status: { not: "SHADOW" } }, orderBy: { createdAt: "asc" } });

  const techniques = kase.mitreTechniques.map((t) => ({ id: t.techniqueId, name: t.technique.name, tactic: TACTIC(t.techniqueId) ?? "" }));
  const tactics = new Set(techniques.map((t) => t.tactic).filter(Boolean));
  const ids = new Set(techniques.map((t) => t.id.split(".")[0]));
  const verdict = out?.verdict ?? kase.verdict ?? "needs_investigation";
  const benign = BENIGN.includes(verdict);

  // Who and what it touched, from the case's own events.
  const ev = await db.securityEvent.findMany({ where: { caseId }, select: { hostName: true, userName: true, sourceIp: true, destIp: true, fileHash: true, filePath: true }, take: 2000 });
  const uniq = (xs: Array<string | null | undefined>) => [...new Set(xs.filter((x): x is string => !!x))].slice(0, 30);
  const scope = {
    hosts: uniq(ev.map((e) => e.hostName)),
    users: uniq(ev.map((e) => e.userName)),
    ips: uniq(ev.flatMap((e) => [e.sourceIp, e.destIp])),
    files: uniq(ev.map((e) => e.fileHash ?? e.filePath)),
    emails: uniq(actions.filter((a) => a.actionType === "BLOCK_SENDER" || a.actionType === "PURGE_EMAIL").map((a) => a.target)),
  };

  // A request for something already in place (the host is isolated already) adds nothing.
  const inPlace = (x: ResponseAction) => x.status !== "EXECUTED" && actions.some((y) => y.status === "EXECUTED" && y.actionType === x.actionType && (y.target ?? "").toLowerCase() === (x.target ?? "").toLowerCase());
  const containment: ContainmentLine[] = actions
    .filter((a) => ["EXECUTED", "IN_PROGRESS", "PENDING_APPROVAL", "MANUAL_REQUIRED"].includes(a.status) && !(a.parameters as { rollbackOf?: string } | null)?.rollbackOf && !inPlace(a))
    .map((a) => ({ action: ACTION_LABEL[a.actionType], target: a.target, status: a.status, by: a.source === "ai" && !a.decidedById ? "AI" : "person", at: a.createdAt.toISOString() }));

  // Lifting what's contained: proposed for a person to approve, never automatic.
  const lift: LiftProposal[] = [];
  const pending = (type: PlaybookActionType, target: string | null) => actions.find((x) => x.actionType === type && x.target === target && ["PENDING_APPROVAL", "SUGGESTED", "IN_PROGRESS"].includes(x.status));
  for (const a of actions.filter((x) => x.status === "EXECUTED" && ["ISOLATE_HOST", "BLOCK_IP", "DISABLE_USER", "REVOKE_AGENT"].includes(x.actionType))) {
    const inverse = ROLLBACK_OF[a.actionType]!;
    const conditions = liftConditions(a.actionType, a.target, tactics, benign);
    let actionId = pending(inverse, a.target)?.id ?? null;
    if (!actionId) {
      const proposal = await recordResponseAction({
        caseId,
        actionType: inverse,
        target: a.target,
        source: "ai",
        status: "PENDING_APPROVAL",
        rationale: `Lift ${ACTION_LABEL[a.actionType].toLowerCase()} once: ${conditions.join("; ")}`,
        policyReason: "Lifting containment is a person's decision",
        parameters: { rollbackOf: a.id, proposedBy: "final_analysis" },
      });
      actionId = proposal.id;
    }
    lift.push({ action: ACTION_LABEL[a.actionType], target: a.target, conditions, actionId, now: benign });
  }

  // Remediation: what removes the threat for good. Steps HELIOS can carry
  // out wait for approval as actions; the rest are tasks with an owner.
  const remediation: RemediationStep[] = [];
  const addAction = async (type: PlaybookActionType, target: string, step: string, why: string, owner: RemediationStep["owner"]) => {
    const existing = actions.find((x) => x.actionType === type && x.target?.toLowerCase() === target.toLowerCase() && !["REJECTED", "FAILED", "BLOCKED"].includes(x.status));
    const id = existing?.id ?? (await recordResponseAction({ caseId, actionType: type, target, source: "ai", status: "PENDING_APPROVAL", rationale: `${step}: ${why}`, policyReason: "Remediation waits for a person's approval", parameters: { proposedBy: "final_analysis" } })).id;
    remediation.push({ step, why, owner, actionId: id });
  };
  const task = (step: string, why: string, owner: RemediationStep["owner"]) => remediation.push({ step, why, owner, actionId: null });

  if (!benign) {
    // The AI's own recommendations that need a person are already on the case.
    for (const a of actions.filter((x) => x.source === "ai" && x.status === "PENDING_APPROVAL" && !(x.parameters as { proposedBy?: string; rollbackOf?: string } | null)?.proposedBy && !(x.parameters as { rollbackOf?: string } | null)?.rollbackOf && !inPlace(x))) {
      remediation.push({ step: `${ACTION_LABEL[a.actionType]}${a.target ? ` ${a.target}` : ""}`, why: a.rationale ?? "Recommended by the investigation", owner: "SOC", actionId: a.id });
    }
    if (has(tactics, "TA0006") || ids.has("T1078") || ids.has("T1110")) for (const u of scope.users.slice(0, 5)) await addAction("RESET_PASSWORD", u, `Reset the password of ${u}`, "credentials were targeted or used in this attack; resetting also ends its sessions", "SOC or client");
    if (ids.has("T1566")) {
      for (const s of scope.emails.slice(0, 5)) await addAction("PURGE_EMAIL", s, `Remove mail from ${s} from every mailbox`, "the phishing message may sit in other inboxes", "SOC");
      task("Tell the recipients what happened and what to look out for", "people who received the message are the next target", "Client IT");
    }
    if (has(tactics, "TA0003")) for (const h of scope.hosts.slice(0, 5)) task(`Remove the persistence found on ${h} (scheduled tasks, services, run keys, startup items), or reimage it`, "the attacker set up a way back in", "SOC or client");
    if (has(tactics, "TA0008")) task("Review every host the compromised accounts signed in to during the window, and isolate any showing the same activity", "the attacker moved between machines", "SOC");
    if (has(tactics, "TA0011", "TA0010")) for (const ip of scope.ips.filter((i) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(i)).slice(0, 5)) await addAction("BLOCK_IP", ip, `Block ${ip} at the perimeter`, "it was used for command and control or exfiltration", "SOC");
    if (has(tactics, "TA0010")) task("Assess what data left and whose: if personal data, start the DPDP breach assessment", "data may have been taken", "SOC or client");
    if (ids.has("T1486") || ids.has("T1490")) task("Restore affected systems from the last clean backup after the hosts are rebuilt", "files were encrypted or recovery was disabled", "Client IT");
    if (ids.has("T1190")) task("Patch or take offline the exposed service the attacker came in through", "the entry point is still open otherwise", "Client IT");
    if (scope.files.length && actions.some((x) => x.actionType === "QUARANTINE_FILE")) task("Search every endpoint for the quarantined file's hash and remove copies", "the same file may be elsewhere", "SOC");
    task("Confirm the timeline with the asset's owner and close the case with a disposition", "closing records the outcome HELIOS learns from", "SOC");
  } else {
    task("Close the case as benign or false positive, and tune the detection if it will recur", "the investigation found no threat", "SOC");
  }

  const findings = out?.key_findings ?? [];
  const entry = timeline[0];
  const rootCause = entry
    ? `${entry.what} (${entry.at})`
    : findings[0]?.finding ?? (benign ? "No malicious cause found." : "Not established from the evidence available: see the open questions.");
  const gapsNote = sweep?.gaps.length ? [`Logs not available: ${sweep.gaps.map((g) => g.label.toLowerCase()).join(", ")}.`] : [];
  return {
    verdict,
    confidence: out?.confidence ?? 0,
    severity: kase.severity,
    summary: out?.summary || kase.title,
    narrative,
    rootCause,
    scope,
    timeline,
    findings,
    techniques,
    containment,
    evidence: sweep,
    lift,
    remediation,
    openQuestions: [...(out?.analyst_next_steps ?? []), ...gapsNote].slice(0, 12),
    basedOn: best ? { agent: best.agentKey, engine: best.engine, model: best.model } : null,
  };
}

export type { ResponseAction };
