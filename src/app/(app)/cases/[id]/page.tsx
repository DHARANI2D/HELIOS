import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, Ban, Crosshair, Fingerprint, Radar, ScrollText, Workflow } from "lucide-react";

import { db } from "@/lib/db";
import { auth } from "@/lib/auth";
import { formatDateTime, formatPercent, formatRelative } from "@/lib/format";
import { CASE_SOURCE_HREF, CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { findMatchingPlaybooks } from "@/lib/playbooks/engine";
import { indicatorVerdict } from "@/lib/threat-intel/service";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, SourceBadge, StatusBadge } from "@/components/shared/case-badges";
import { JsonView } from "@/components/shared/json-view";
import { CaseActions } from "@/components/cases/case-actions";
import { CaseTimeline } from "@/components/cases/case-timeline";
import { SourcePanel } from "@/components/cases/source-panel";
import { ExecutionDecision } from "@/components/playbooks/execution-decision";
import { RunPlaybookButton } from "@/components/playbooks/run-playbook-button";
import { RecheckButton } from "@/components/threat-intel/recheck-button";
import { VerdictBadge } from "@/components/threat-intel/verdict-badge";

const EXECUTION_VARIANT = {
  PENDING_APPROVAL: "warning",
  RUNNING: "secondary",
  SUCCEEDED: "success",
  FAILED: "destructive",
  REJECTED: "outline",
} as const;

export default async function CaseDetailPage({ params }: PageProps<"/cases/[id]">) {
  const { id } = await params;
  const session = await auth();

  const kase = await db.case.findUnique({
    where: { id },
    include: {
      assignedTo: { select: { id: true, name: true, email: true } },
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: [{ occurredAt: "asc" }, { createdAt: "asc" }] },
      mitreTechniques: { include: { technique: { include: { tactic: true } } } },
      indicators: { include: { indicator: true } },
      playbookRuns: {
        orderBy: { startedAt: "desc" },
        include: { playbook: { select: { name: true } }, approvals: { include: { approver: { select: { name: true, email: true } } } } },
      },
      auditLogs: { orderBy: { seq: "desc" }, take: 25, include: { actor: { select: { name: true, email: true } } } },
      _count: { select: { events: true } },
    },
  });
  if (!kase) notFound();

  const [matching, events] = await Promise.all([
    findMatchingPlaybooks(kase.id),
    db.securityEvent.findMany({ where: { caseId: kase.id }, orderBy: { timestamp: "asc" }, take: 50 }),
  ]);
  const ranPlaybookIds = new Set(kase.playbookRuns.map((r) => r.playbookId));
  const suggestions = matching.filter((p) => !ranPlaybookIds.has(p.id));

  return (
    <div className="flex flex-col gap-6">
      <div>
        <Button variant="ghost" size="sm" asChild className="-ml-2">
          <Link href={CASE_SOURCE_HREF[kase.sourceType]}>
            <ArrowLeft /> {CASE_SOURCE_LABEL[kase.sourceType]}
          </Link>
        </Button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={kase.severity} />
              <StatusBadge status={kase.status} />
              <SourceBadge source={kase.sourceType} />
              {kase.verdict && <Badge variant="outline" className="capitalize">Verdict: {kase.verdict}</Badge>}
            </div>
            <CardTitle className="mt-2 text-lg leading-snug">{kase.title}</CardTitle>
            {kase.summary && <CardDescription className="whitespace-pre-wrap">{kase.summary}</CardDescription>}
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            <Meta label="Created">{formatDateTime(kase.createdAt)}</Meta>
            <Meta label="Updated">{formatRelative(kase.updatedAt)}</Meta>
            <Meta label="Risk score">{kase.riskScore != null ? Math.round(kase.riskScore) : "—"}</Meta>
            <Meta label="Confidence">{formatPercent(kase.confidence)}</Meta>
            <Meta label="Assignee">{kase.assignedTo ? (kase.assignedTo.name ?? kase.assignedTo.email) : "Unassigned"}</Meta>
            <Meta label="Source ref"><span className="font-mono text-xs break-all">{kase.sourceRef ?? "—"}</span></Meta>
            <Meta label="Linked events">{kase._count.events}</Meta>
            <Meta label="Resolved">{kase.resolvedAt ? formatDateTime(kase.resolvedAt) : "—"}</Meta>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Triage</CardTitle>
          </CardHeader>
          <CardContent>
            <CaseActions
              caseId={kase.id}
              status={kase.status}
              severity={kase.severity}
              assignedToMe={!!session?.user?.id && kase.assignedToId === session.user.id}
            />
          </CardContent>
        </Card>
      </div>

      {kase.rootCauseNarrative && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Root cause</CardTitle>
          </CardHeader>
          <CardContent className="text-sm whitespace-pre-wrap">{kase.rootCauseNarrative}</CardContent>
        </Card>
      )}

      <SourcePanel kase={kase} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Radar className="size-4" /> Detections ({kase.detections.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {kase.detections.length === 0 ? (
                <p className="text-sm text-muted-foreground">No detections recorded.</p>
              ) : (
                <ul className="divide-y">
                  {kase.detections.map((d) => (
                    <li key={d.id} className="py-3 first:pt-0 last:pb-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={d.severity} />
                        <Badge variant="outline" className="font-mono text-[10px]">{d.source}</Badge>
                        <span className="text-xs text-muted-foreground">{formatDateTime(d.createdAt)}</span>
                      </div>
                      <p className="mt-1 text-sm font-medium">{d.title}</p>
                      <details className="mt-1">
                        <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Evidence · rule {d.ruleId}</summary>
                        <JsonView value={d.evidence} className="mt-2" />
                      </details>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Timeline</CardTitle>
              <CardDescription>Telemetry, detections, playbook actions, and analyst notes in order.</CardDescription>
            </CardHeader>
            <CardContent>
              <CaseTimeline entries={kase.timeline} />
            </CardContent>
          </Card>

          {events.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Linked telemetry</CardTitle>
                <CardDescription>
                  {kase._count.events > events.length ? `First ${events.length} of ${kase._count.events} events` : `${events.length} events`}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>User / host</TableHead>
                      <TableHead>Process / network</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((e) => (
                      <TableRow key={e.id} className="text-xs">
                        <TableCell className="tabular-nums">{formatDateTime(e.timestamp)}</TableCell>
                        <TableCell>{e.platform ?? e.source}</TableCell>
                        <TableCell className="font-mono">{e.eventType}</TableCell>
                        <TableCell>{[e.userName, e.hostName].filter(Boolean).join(" @ ") || "—"}</TableCell>
                        <TableCell className="max-w-xs truncate font-mono" title={e.commandLine ?? undefined}>
                          {e.commandLine ?? e.processName ?? ([e.sourceIp, e.destIp].filter(Boolean).join(" → ") + (e.destPort ? `:${e.destPort}` : "") || "—")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Crosshair className="size-4" /> MITRE ATT&amp;CK</CardTitle>
            </CardHeader>
            <CardContent>
              {kase.mitreTechniques.length === 0 ? (
                <p className="text-sm text-muted-foreground">No techniques mapped.</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {kase.mitreTechniques.map(({ technique, confidence }) => (
                    <li key={technique.id} className="flex items-start justify-between gap-2 text-sm">
                      <div>
                        <span className="font-mono text-xs text-muted-foreground">{technique.id}</span>{" "}
                        <span className="font-medium">{technique.name}</span>
                        <p className="text-xs text-muted-foreground">{technique.tactic.name}</p>
                      </div>
                      {confidence != null && <span className="text-xs tabular-nums text-muted-foreground">{formatPercent(confidence)}</span>}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Fingerprint className="size-4" /> Indicators ({kase.indicators.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {kase.indicators.length === 0 ? (
                <p className="text-sm text-muted-foreground">No indicators extracted.</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {kase.indicators.map(({ indicator, role }) => (
                    <li key={indicator.id} className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs" title={indicator.value}>{indicator.value}</p>
                        <p className="text-[11px] text-muted-foreground">
                          {indicator.type}{role ? ` · ${role.replaceAll("_", " ")}` : ""}
                          {indicator.blockedAt && (
                            <span className="ml-1 inline-flex items-center gap-0.5 text-destructive"><Ban className="size-3" /> blocked</span>
                          )}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-1">
                        <VerdictBadge verdict={indicatorVerdict(indicator)} />
                        <RecheckButton indicatorId={indicator.id} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Workflow className="size-4" /> Response playbooks</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              {kase.playbookRuns.length === 0 && suggestions.length === 0 && (
                <p className="text-sm text-muted-foreground">No playbooks matched this case.</p>
              )}
              {kase.playbookRuns.map((run) => (
                <div key={run.id} className="rounded-md border p-3">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-sm font-medium">{run.playbook.name}</p>
                    <Badge variant={EXECUTION_VARIANT[run.status]}>{run.status.replaceAll("_", " ").toLowerCase()}</Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {run.triggeredBy} · {formatRelative(run.startedAt)}
                    {run.approvals.map((a) => ` · ${a.decision} by ${a.approver.name ?? a.approver.email}`).join("")}
                  </p>
                  {run.error && <p className="mt-1 text-xs text-destructive">{run.error}</p>}
                  {Array.isArray(run.results) && run.results.length > 0 && (
                    <ul className="mt-2 space-y-0.5 text-xs">
                      {(run.results as Array<{ action: string; summary: string; simulated?: boolean; status: string }>).map((r, i) => (
                        <li key={i} className={r.status === "failed" ? "text-destructive" : undefined}>
                          <span className="font-medium">{r.action}</span>: {r.summary}
                          {r.simulated && <span className="text-muted-foreground"> (simulated)</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                  {run.status === "PENDING_APPROVAL" && (
                    <div className="mt-3">
                      <ExecutionDecision executionId={run.id} />
                    </div>
                  )}
                </div>
              ))}
              {suggestions.length > 0 && (
                <div className="flex flex-col gap-2">
                  <p className="text-xs font-medium text-muted-foreground">Matching playbooks not yet run</p>
                  {suggestions.map((p) => (
                    <div key={p.id} className="flex items-center justify-between gap-2 text-sm">
                      <span className="min-w-0 truncate">{p.name}</span>
                      <RunPlaybookButton caseId={kase.id} playbookId={p.id} />
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><ScrollText className="size-4" /> Audit trail</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="flex flex-col gap-1.5 text-xs">
                {kase.auditLogs.map((log) => (
                  <li key={log.id} className="flex justify-between gap-2">
                    <span className="font-mono">{log.action}</span>
                    <span className="shrink-0 text-muted-foreground">
                      {log.actor ? (log.actor.name ?? log.actor.email) : "system"} · {formatRelative(log.createdAt)}
                    </span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="mt-0.5">{children}</div>
    </div>
  );
}
