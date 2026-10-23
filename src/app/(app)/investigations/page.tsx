import Link from "next/link";
import { Bot, Cpu, Search } from "lucide-react";

import { db } from "@/lib/db";
import { claudeConfigured, INVESTIGATION_MODEL } from "@/lib/investigations/agents";
import type { InvestigationMetadata } from "@/lib/investigations/service";
import { formatPercent, formatRelative } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, StatusBadge } from "@/components/shared/case-badges";
import { EmptyState } from "@/components/shared/empty-state";
import { NewInvestigationForm } from "@/components/investigations/new-investigation-form";

const PIPELINE_VARIANT = { queued: "outline", running: "secondary", completed: "success", failed: "destructive" } as const;

export default async function InvestigationsPage() {
  const investigations = await db.case.findMany({
    where: { sourceType: "SOC_INVESTIGATION" },
    orderBy: { createdAt: "desc" },
    take: 50,
  });
  const claude = claudeConfigured();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">New investigation</CardTitle>
            <CardDescription>
              Upload forensic telemetry; HELIOS normalizes it, builds the process graph, and runs triage → root cause → adversarial QA → report.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NewInvestigationForm />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Analysis engine</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            {claude ? (
              <div className="flex items-start gap-3">
                <Bot className="mt-0.5 size-5 shrink-0" />
                <div>
                  <p className="font-medium">Claude agent swarm</p>
                  <p className="text-xs text-muted-foreground">
                    Model <code>{INVESTIGATION_MODEL}</code> with structured outputs; the deterministic engine grounds every agent and takes over any stage whose model call fails.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex items-start gap-3">
                <Cpu className="mt-0.5 size-5 shrink-0" />
                <div>
                  <p className="font-medium">Deterministic forensic engine</p>
                  <p className="text-xs text-muted-foreground">
                    20 rules covering macro droppers, encoded PowerShell, LOLBins, credential dumping, persistence, lateral movement, C2, and
                    ransomware precursors. Set <code>ANTHROPIC_API_KEY</code> to add the Claude agent swarm.
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Investigations</CardTitle>
        </CardHeader>
        <CardContent>
          {investigations.length === 0 ? (
            <EmptyState icon={Search} title="No investigations yet" description="Start one above — try the sample to see the full pipeline." />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Investigation</TableHead>
                  <TableHead>Pipeline</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Events</TableHead>
                  <TableHead className="text-right">Confidence</TableHead>
                  <TableHead className="text-right">Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {investigations.map((c) => {
                  const meta = c.metadata as unknown as InvestigationMetadata | null;
                  return (
                    <TableRow key={c.id}>
                      <TableCell><SeverityBadge severity={c.severity} /></TableCell>
                      <TableCell className="max-w-md">
                        <Link href={`/cases/${c.id}`} className="line-clamp-1 font-medium hover:underline">{c.title}</Link>
                        {c.verdict && <span className="text-xs capitalize text-muted-foreground">Verdict: {c.verdict}</span>}
                      </TableCell>
                      <TableCell>
                        {meta?.pipeline ? (
                          <div className="flex items-center gap-1.5">
                            <Badge variant={PIPELINE_VARIANT[meta.pipeline.status]}>{meta.pipeline.status}</Badge>
                            <span className="text-xs text-muted-foreground">{meta.pipeline.engine === "claude" ? "Claude" : "deterministic"}</span>
                          </div>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                      <TableCell><StatusBadge status={c.status} /></TableCell>
                      <TableCell className="text-right tabular-nums">{meta?.input?.eventCount ?? "—"}</TableCell>
                      <TableCell className="text-right tabular-nums">{formatPercent(c.confidence)}</TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(c.createdAt)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
