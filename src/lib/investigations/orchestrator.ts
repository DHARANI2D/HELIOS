import { runTriageAgent, runRcaAgent, runQaAgent, runReportAgent } from "./agents";
import type { EntityGraph, SwarmResult } from "./types";

// Ported from asip's agents/orchestrator.py — a LangGraph StateGraph with
// 4 nodes and one conditional retry edge (qa -> rca, up to 3 iterations).
// Implemented here as a plain async function rather than pulling in
// LangGraph.js + @langchain/core: the original graph has no parallel
// branches, subgraphs, or tool-calling — it's a linear pipeline with one
// bounded loop, which a graph orchestration framework doesn't buy anything
// for. Same control flow, same node responsibilities, far less dependency
// weight and no framework-API risk.

export async function runInvestigationSwarm(
  alertTitle: string,
  alertDetails: string,
  graphData: EntityGraph,
  sampleLogs: unknown[],
): Promise<SwarmResult> {
  const triage = await runTriageAgent(alertTitle, alertDetails);

  let rca = await runRcaAgent(triage, graphData, sampleLogs);
  let qa = await runQaAgent(rca, sampleLogs);
  let qaIterations = 1;

  while (!qa.is_valid && qaIterations < 3) {
    rca = await runRcaAgent(triage, graphData, sampleLogs, qa.issues);
    qa = await runQaAgent(rca, sampleLogs);
    qaIterations++;
  }

  const finalReport = await runReportAgent(triage, rca, qa);

  return { triage, rca, qa, qaIterations, finalReport };
}
