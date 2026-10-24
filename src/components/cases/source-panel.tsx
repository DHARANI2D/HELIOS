import Link from "next/link";
import type { Case } from "@prisma/client";

import { db } from "@/lib/db";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Markdown } from "@/components/shared/markdown";
import { SeverityBadge } from "@/components/shared/case-badges";
import { PipelineProgress } from "@/components/investigations/pipeline-progress";
import { ProcessGraph } from "@/components/investigations/process-graph";
import { EmailAnalysisPanel } from "@/components/forensics/email-analysis-panel";
import type { InvestigationMetadata } from "@/lib/investigations/service";

// Source-specific detail for a case. Every source shares the generic case
// view (detections, timeline, MITRE, IOCs, playbooks); this adds what only
// that module knows about.
export async function SourcePanel({ kase }: { kase: Case }) {
  switch (kase.sourceType) {
    case "AGENT_GOVERNANCE":
      return <AgentPanel kase={kase} />;
    case "SOC_INVESTIGATION":
      return <InvestigationPanel kase={kase} />;
    case "EMAIL_ANALYSIS":
      return <EmailAnalysisPanel kase={kase} />;
    default:
      return null;
  }
}

async function AgentPanel({ kase }: { kase: Case }) {
  if (!kase.sourceRef) return null;
  const agent = await db.agent.findUnique({ where: { id: kase.sourceRef } });
  if (!agent) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">AI agent</CardTitle>
        <CardDescription>
          Workload identity behind this case — manage it from <Link href="/governance" className="underline">Agent Governance</Link>.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 text-sm sm:grid-cols-3">
        <div>
          <p className="text-xs text-muted-foreground">Agent</p>
          <p className="font-medium">{agent.name}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Status</p>
          <Badge variant={agent.status === "REVOKED" ? "destructive" : "secondary"}>{agent.status}</Badge>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Trust · Level L{agent.level}</p>
          <Progress value={agent.trust} className="mt-2" />
        </div>
      </CardContent>
    </Card>
  );
}

function InvestigationPanel({ kase }: { kase: Case }) {
  const meta = kase.metadata as unknown as InvestigationMetadata | null;
  if (!meta?.pipeline) return null;
  const { pipeline, input, triage, qa, report, graph, findings } = meta;

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Investigation pipeline</CardTitle>
          <CardDescription>
            {pipeline.engine !== "heuristic"
              ? `Multi-agent analysis on ${pipeline.engineName ? `${pipeline.engineName}, ` : ""}${pipeline.model} (triage → RCA ⇄ adversarial QA → report).`
              : "Deterministic forensic engine (connect Claude or a local model under AI Agents to run the agent swarm)."}{" "}
            {input.eventCount} events from {input.files.map((f) => `${f.name} (${f.platform}, ${f.events})`).join(", ")}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <PipelineProgress caseId={kase.id} pipeline={pipeline} />
        </CardContent>
      </Card>

      {triage && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Triage</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2 text-sm">
              <p><span className="text-muted-foreground">Classification:</span> {triage.alert_type}</p>
              <p><span className="text-muted-foreground">Tactic:</span> {triage.mitre_tactic}</p>
              <p>{triage.initial_hypothesis}</p>
              {triage.evidence_required.length > 0 && (
                <p className="text-xs text-muted-foreground">Evidence required: {triage.evidence_required.join(", ")}</p>
              )}
            </CardContent>
          </Card>
          {qa && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Adversarial QA</CardTitle>
                <CardDescription>
                  {qa.is_valid
                    ? `Validated after ${pipeline.qaIterations} round(s): every timeline claim traces to an event.`
                    : `${qa.issues.length} unresolved issue(s) after ${pipeline.qaIterations} round(s).`}
                </CardDescription>
              </CardHeader>
              <CardContent className="text-sm">
                {qa.issues.length > 0 && (
                  <ul className="mb-2 list-disc space-y-1 pl-5 text-destructive">
                    {qa.issues.map((i, n) => <li key={n}>{i}</li>)}
                  </ul>
                )}
                <details>
                  <summary className="cursor-pointer text-xs text-muted-foreground">{qa.validated_evidence.length} validated claims</summary>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-xs">
                    {qa.validated_evidence.map((v, n) => <li key={n}>{v}</li>)}
                  </ul>
                </details>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {findings && findings.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Forensic findings</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {findings.map((f) => (
                <li key={f.ruleId} className="flex items-start gap-3 py-2 first:pt-0 last:pb-0">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 text-sm">
                    <p className="font-medium">{f.title} <span className="font-mono text-xs text-muted-foreground">{f.techniques.join(", ")}</span></p>
                    <p className="text-muted-foreground">{f.description} ({f.eventCount} event{f.eventCount === 1 ? "" : "s"})</p>
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {graph && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Process lineage</CardTitle>
            <CardDescription>Processes, network destinations, DNS lookups, and dropped files correlated by host and PID.</CardDescription>
          </CardHeader>
          <CardContent>
            <ProcessGraph graph={graph} />
          </CardContent>
        </Card>
      )}

      {report && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Incident report</CardTitle>
          </CardHeader>
          <CardContent>
            <Markdown>{report}</Markdown>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
