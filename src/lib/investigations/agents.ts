import { invokeAgent, parseJsonResponse } from "./llm";
import type { TriageResult, RcaResult, QaResult, EntityGraph } from "./types";

// Ported from asip's agents/{triage,rca,qa,report}_agent.py — same system
// prompts, same JSON-object contract per agent.

export async function runTriageAgent(alertTitle: string, alertDetails: string): Promise<TriageResult> {
  const systemPrompt = `You are a Tier 3 SOC Analyst. Your task is to triage and categorize the incoming cybersecurity alert.
Return a JSON object with the following fields:
{
  "alert_type": "string (e.g. Encoded PowerShell, Suspicious Login)",
  "severity": "string (critical, high, medium, low)",
  "mitre_tactic": "string (e.g. Execution TA0002)",
  "initial_hypothesis": "string (describe how this happened and likely parent-child processes)",
  "evidence_required": ["list of strings indicating what logs we need to search for (e.g. process_create, network_connect)"]
}
Ensure the output is valid JSON and nothing else.`;

  const userPrompt = `Alert Title: ${alertTitle}\nAlert Details: ${alertDetails}`;
  const raw = await invokeAgent(systemPrompt, userPrompt, { json: true });

  return parseJsonResponse<TriageResult>(raw, {
    alert_type: "Suspicious Threat Alert",
    severity: "high",
    mitre_tactic: "Unknown Tactic",
    initial_hypothesis: "Failed to parse triage reasoning.",
    evidence_required: ["process_create", "network_connect"],
  });
}

export async function runRcaAgent(
  triageData: TriageResult,
  graphData: EntityGraph,
  sampleLogs: unknown[],
  qaFeedback?: string[],
): Promise<RcaResult> {
  const systemPrompt = `You are a Lead Incident Responder. Your task is to perform a detailed Root Cause Analysis (RCA) on the forensic graph and raw logs.
Connect the nodes chronologically to explain the attack vector.
Return a JSON object with the following fields:
{
  "root_cause": "Detailed explanation of the initial entry point, process executions, and malicious connections.",
  "timeline": [
     "HH:MM:SS - Description of event with log reference (e.g. PID 4512 powershell connected to 185.220.101.5)"
  ],
  "confidence_score": 0.95
}
Ensure the output is valid JSON and nothing else.`;

  const triageInput = qaFeedback?.length
    ? {
        ...triageData,
        initial_hypothesis: `${triageData.initial_hypothesis}\nValidation feedback from QA agent (please correct these details): ${qaFeedback.join("; ")}`,
      }
    : triageData;

  const userPrompt = `Triage Assessment: ${JSON.stringify(triageInput, null, 2)}
Forensic Graph: ${JSON.stringify(graphData, null, 2)}
Ingested Logs: ${JSON.stringify(sampleLogs.slice(0, 50), null, 2)}`;

  const raw = await invokeAgent(systemPrompt, userPrompt, { json: true });

  return parseJsonResponse<RcaResult>(raw, {
    root_cause: "Failed to perform RCA reasoning.",
    timeline: ["00:00:00 - Timeline parsing failed"],
    confidence_score: 0.5,
  });
}

export async function runQaAgent(rcaData: RcaResult, sampleLogs: unknown[]): Promise<QaResult> {
  const systemPrompt = `You are an Adversarial QA Security Validator. Your job is to verify that the Root Cause Analysis is factually correct.
Verify:
1. Every claim in root_cause or timeline corresponds to an actual event in the logs.
2. The sequence of events makes chronological sense.
Return a JSON object with the following fields:
{
  "is_valid": true/false,
  "validated_evidence": ["List of claims confirmed by specific log lines"],
  "issues": ["List of problems found"]
}
Ensure the output is valid JSON and nothing else.`;

  const userPrompt = `RCA Report: ${JSON.stringify(rcaData, null, 2)}
Ingested Logs: ${JSON.stringify(sampleLogs.slice(0, 50), null, 2)}`;

  const raw = await invokeAgent(systemPrompt, userPrompt, { json: true });

  return parseJsonResponse<QaResult>(raw, {
    is_valid: false,
    validated_evidence: [],
    issues: ["QA verification failed to parse."],
  });
}

export async function runReportAgent(
  triageData: TriageResult,
  rcaData: RcaResult,
  qaData: QaResult,
): Promise<string> {
  const systemPrompt = `You are a Principal Security Consultant. Compile a formal, highly-detailed SOC Incident Report in Markdown format.
Focus on clear structure, exact evidence references, and actionable recommendations.
Your output should have:
1. Executive Summary
2. Root Cause Analysis & Timeline
3. MITRE ATT&CK Mapping
4. Containment & Mitigation Playbook (Immediate, Short-term, Long-term actions)
5. Evidence Verification Notes (QA approval summary)`;

  const userPrompt = `Triage: ${JSON.stringify(triageData)}
RCA: ${JSON.stringify(rcaData)}
QA Validation: ${JSON.stringify(qaData)}`;

  return invokeAgent(systemPrompt, userPrompt);
}
