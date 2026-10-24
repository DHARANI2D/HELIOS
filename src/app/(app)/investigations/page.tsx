import Link from "next/link";
import { Bot, Cpu, HardDrive, Search } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { caseScope, selectedTenantId } from "@/lib/access";
import { tenantOptions } from "@/lib/tenants";
import { resolveProvider } from "@/lib/ai/resolve";
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

const ENGINE_LABEL = { claude: "Claude", local: "local model", heuristic: "deterministic" } as const;

export default async function InvestigationsPage() {
  const user = await pageGuard("investigations.run");
  const [investigations, provider, tenants, defaultTenantId] = await Promise.all([
    db.case.findMany({
      where: { AND: [await caseScope(user), { sourceType: "SOC_INVESTIGATION" }] },
      orderBy: { createdAt: "desc" },
      take: 50,
      include: { tenant: { select: { name: true } } },
    }),
    resolveProvider("investigation"),
    tenantOptions(),
    selectedTenantId(user),
  ]);

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
            <NewInvestigationForm tenants={tenants} defaultTenantId={defaultTenantId} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Analysis engine</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            {provider ? (
              <div className="flex items-start gap-3">
                {provider.isLocal ? <HardDrive className="mt-0.5 size-5 shrink-0" /> : <Bot className="mt-0.5 size-5 shrink-0" />}
                <div>
                  <p className="font-medium">{provider.isLocal ? "Local model agent swarm" : "Claude agent swarm"}</p>
                  <p className="text-xs text-muted-foreground">
                    {provider.name}, model <code>{provider.model}</code>, with structured outputs; the deterministic engine grounds every agent and takes over any stage whose model call fails.
                    Change it under <Link href="/ai" className="underline">AI Agents</Link>.
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
                    ransomware precursors. Connect Claude or a local model under <Link href="/ai" className="underline">AI Agents</Link> to add the agent swarm.
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
                  <TableHead>Client</TableHead>
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
                      <TableCell className="text-xs">{c.tenant?.name ?? <span className="text-muted-foreground">Internal</span>}</TableCell>
                      <TableCell>
                        {meta?.pipeline ? (
                          <div className="flex items-center gap-1.5">
                            <Badge variant={PIPELINE_VARIANT[meta.pipeline.status]}>{meta.pipeline.status}</Badge>
                            <span className="text-xs text-muted-foreground">{ENGINE_LABEL[meta.pipeline.engine] ?? meta.pipeline.engine}</span>
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
