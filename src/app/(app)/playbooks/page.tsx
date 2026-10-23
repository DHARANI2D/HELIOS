import Link from "next/link";
import { CheckCircle2, Clock, ListChecks, Workflow } from "lucide-react";
import type { PlaybookActionType } from "@prisma/client";

import { db } from "@/lib/db";
import { auth } from "@/lib/auth";
import { describeTrigger, parseTrigger, type TriggerCondition } from "@/lib/playbooks/trigger";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
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
import { SeverityBadge } from "@/components/shared/case-badges";
import { EmptyState } from "@/components/shared/empty-state";
import { ExecutionDecision } from "@/components/playbooks/execution-decision";
import { PlaybookEditor } from "@/components/playbooks/playbook-editor";
import { PlaybookControls } from "@/components/playbooks/playbook-controls";

const EXECUTION_VARIANT = {
  PENDING_APPROVAL: "warning",
  RUNNING: "secondary",
  SUCCEEDED: "success",
  FAILED: "destructive",
  REJECTED: "outline",
} as const;

async function getExecutionStats() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [runs24h, succeeded24h] = await Promise.all([
    db.playbookExecution.count({ where: { startedAt: { gte: since }, status: { not: "PENDING_APPROVAL" } } }),
    db.playbookExecution.count({ where: { startedAt: { gte: since }, status: "SUCCEEDED" } }),
  ]);
  return { runs24h, succeeded24h };
}

export default async function PlaybooksPage() {
  const session = await auth();
  const isAdmin = session?.user?.role === "ADMIN";
  const [playbooks, pending, recent, { runs24h, succeeded24h }] = await Promise.all([
    db.playbook.findMany({
      orderBy: [{ enabled: "desc" }, { priority: "desc" }, { name: "asc" }],
      include: { actions: { orderBy: { order: "asc" } }, _count: { select: { executions: true } } },
    }),
    db.playbookExecution.findMany({
      where: { status: "PENDING_APPROVAL" },
      orderBy: { startedAt: "asc" },
      include: { playbook: { select: { name: true } }, case: { select: { id: true, title: true, severity: true } } },
    }),
    db.playbookExecution.findMany({
      where: { status: { not: "PENDING_APPROVAL" } },
      orderBy: { startedAt: "desc" },
      take: 25,
      include: { playbook: { select: { name: true } }, case: { select: { id: true, title: true } } },
    }),
    getExecutionStats(),
  ]);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Enabled playbooks" value={playbooks.filter((p) => p.enabled).length} icon={Workflow} />
        <StatTile label="Awaiting approval" value={pending.length} icon={Clock} tone={pending.length ? "warning" : "default"} />
        <StatTile label="Executions (24h)" value={runs24h} icon={ListChecks} />
        <StatTile label="Success rate (24h)" value={runs24h ? `${Math.round((succeeded24h / runs24h) * 100)}%` : "—"} icon={CheckCircle2} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Approval queue</CardTitle>
          <CardDescription>
            Containment that requires a human decision. {isAdmin ? "Approving runs the playbook immediately." : "Only admins can approve."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {pending.length === 0 ? (
            <p className="text-sm text-muted-foreground">Nothing awaiting approval.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Case</TableHead>
                  <TableHead>Playbook</TableHead>
                  <TableHead>Requested</TableHead>
                  <TableHead className="text-right">Decision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pending.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="max-w-md">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={p.case.severity} />
                        <Link href={`/cases/${p.case.id}`} className="line-clamp-1 hover:underline">{p.case.title}</Link>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm">{p.playbook.name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{p.triggeredBy} · {formatRelative(p.startedAt)}</TableCell>
                    <TableCell className="flex justify-end"><ExecutionDecision executionId={p.id} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold">Playbooks</h2>
          <p className="text-xs text-muted-foreground">Evaluated against every case on creation and whenever new evidence correlates into it.</p>
        </div>
        {isAdmin && <PlaybookEditor />}
      </div>

      {playbooks.length === 0 ? (
        <Card>
          <CardContent>
            <EmptyState icon={Workflow} title="No playbooks" description="Run npm run db:seed to install the starter set, or create one." />
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {playbooks.map((pb) => {
            const trigger = parseTrigger(pb.triggerCondition);
            return (
              <Card key={pb.id} className={pb.enabled ? undefined : "opacity-60"}>
                <CardHeader>
                  <div className="flex flex-wrap items-center gap-2">
                    {pb.requireApproval ? (
                      <Badge variant="warning">Approval required</Badge>
                    ) : pb.autoExecute ? (
                      <Badge>Auto-execute</Badge>
                    ) : (
                      <Badge variant="outline">Manual</Badge>
                    )}
                    <Badge variant="outline" className="font-normal">priority {pb.priority}</Badge>
                    <span className="text-xs text-muted-foreground">{pb._count.executions} runs</span>
                  </div>
                  <CardTitle className="mt-1 text-base">{pb.name}</CardTitle>
                  {pb.description && <CardDescription>{pb.description}</CardDescription>}
                </CardHeader>
                <CardContent className="flex flex-col gap-3">
                  <div className="flex flex-wrap gap-1.5">
                    {trigger ? (
                      describeTrigger(trigger).map((c) => (
                        <span key={c} className="rounded-md bg-muted px-2 py-0.5 font-mono text-[11px]">{c}</span>
                      ))
                    ) : (
                      <span className="text-xs text-destructive">Invalid trigger — this playbook never matches</span>
                    )}
                  </div>
                  <ol className="list-decimal space-y-0.5 pl-5 text-sm">
                    {pb.actions.map((a) => (
                      <li key={a.id}>
                        {a.name} <span className="font-mono text-[11px] text-muted-foreground">{a.actionType}</span>
                      </li>
                    ))}
                  </ol>
                  {isAdmin && (
                    <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3">
                      <PlaybookControls playbookId={pb.id} enabled={pb.enabled} />
                      <PlaybookEditor
                        playbook={{
                          id: pb.id,
                          name: pb.name,
                          description: pb.description,
                          triggerCondition: (trigger ?? {}) as TriggerCondition,
                          autoExecute: pb.autoExecute,
                          requireApproval: pb.requireApproval,
                          priority: pb.priority,
                          actions: pb.actions.map((a) => ({
                            name: a.name,
                            actionType: a.actionType as PlaybookActionType,
                            parameters: (a.parameters ?? {}) as Record<string, string | number>,
                          })),
                        }}
                      />
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent executions</CardTitle>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">No executions yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Playbook</TableHead>
                  <TableHead>Case</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead className="text-right">When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recent.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell className="text-sm">{r.playbook.name}</TableCell>
                    <TableCell className="max-w-xs">
                      <Link href={`/cases/${r.case.id}`} className="line-clamp-1 text-sm hover:underline">{r.case.title}</Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant={EXECUTION_VARIANT[r.status]}>{r.status.replaceAll("_", " ").toLowerCase()}</Badge>
                      {r.error && <p className="mt-1 text-xs text-destructive">{r.error}</p>}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{r.triggeredBy}</TableCell>
                    <TableCell className="text-right text-xs text-muted-foreground">{formatRelative(r.startedAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
