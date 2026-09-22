export interface TriageResult {
  alert_type: string;
  severity: "critical" | "high" | "medium" | "low" | string;
  mitre_tactic: string;
  initial_hypothesis: string;
  evidence_required: string[];
}

export interface RcaResult {
  root_cause: string;
  timeline: string[];
  confidence_score: number;
}

export interface QaResult {
  is_valid: boolean;
  validated_evidence: string[];
  issues: string[];
}

export interface GraphNode {
  id: string;
  type: "process" | "ip" | "file";
  label: string;
  [key: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface EntityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SwarmResult {
  triage: TriageResult;
  rca: RcaResult;
  qa: QaResult;
  qaIterations: number;
  finalReport: string;
}
