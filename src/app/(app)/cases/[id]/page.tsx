import Link from "next/link";
import { ArrowLeft, Ban, Bot, Building2, Crosshair, Download, Eye, Fingerprint, Link2, Radar, ScrollText, ShieldAlert, Users, Workflow } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard, type SessionUser } from "@/lib/session";
import { assertCaseAccess } from "@/lib/access";
import { can, roleLabel } from "@/lib/rbac";
import { formatDateTime, formatPercent, formatRelative } from "@/lib/format";
import { CASE_SOURCE_HREF, CASE_SOURCE_LABEL, CLOSED_STATUSES } from "@/lib/cases/labels";
import { dispositionLabel } from "@/lib/shadow/service";
import { formatMinutes, parsePlan } from "@/lib/plans";
import { recommendPlaybooks } from "@/lib/playbooks/recommend";
import { findRelatedCases } from "@/lib/cases/related";
import { indicatorVerdict } from "@/lib/threat-intel/service";
import { AGENT_TYPES, DISPATCHABLE_AGENTS } from "@/lib/ai/catalog";
import { resolveAgent } from "@/lib/ai/resolve";
import { gatherEvidence } from "@/lib/ai/evidence";
import { PROPOSABLE_ACTIONS, matchTarget, type GroundingReport, type TriageOutput } from "@/lib/ai/triage";
import { ACTION_LABEL, ROLLBACK_OF } from "@/lib/response/executor";
import { approvalsOf } from "@/lib/response/service";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TestBadge } from "@/components/shared/test-badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge, SourceBadge, StatusBadge } from "@/components/shared/case-badges";
import { AiStatusBadge, DomainBadge, SlaChip, TierBadge } from "@/components/shared/case-chips";
import { JsonView } from "@/components/shared/json-view";
import { CaseTimeline } from "@/components/cases/case-timeline";
import { SourcePanel } from "@/components/cases/source-panel";
import { TriagePanel } from "@/components/cases/triage-panel";
import { CollabActions } from "@/components/cases/collab-actions";
import { Discussion } from "@/components/cases/discussion";
import { AgentDispatch, AiFeedback } from "@/components/cases/ai-controls";
import { ResponseActions } from "@/components/cases/response-actions";
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

const VERDICT_TONE: Record<string, string> = {
  true_positive: "text-destructive",
  suspicious: "text-warning-ink",
  benign: "text-success-ink",
  needs_investigation: "text-info-ink",
};

async function loadCasePage(id: string, user: SessionUser) {
  const now = new Date();
  const kase = await db.case.findUniqueOrThrow({
    where: { id },
    include: {
      tenant: { select: { id: true, name: true, plan: true, isTest: true } },
      assignedTo: { select: { id: true, name: true, email: true } },
      detections: { orderBy: { createdAt: "desc" } },
      timeline: { orderBy: [{ occurredAt: "asc" }, { createdAt: "asc" }] },
      mitreTechniques: { include: { technique: { include: { tactic: true } } } },
      indicators: { include: { indicator: true } },
      playbookRuns: {
        orderBy: { startedAt: "desc" },
        include: { playbook: { select: { name: true } }, approvals: { include: { approver: { select: { name: true, email: true } } } } },
      },
      comments: { where: user.isClient ? { internal: false } : {}, orderBy: { createdAt: "asc" } },
      watchers: { include: { user: { select: { id: true, name: true, email: true } } } },
      responseActions: { orderBy: { createdAt: "asc" } },
      aiRuns: { orderBy: { createdAt: "desc" }, take: 6 },
      aiOutcomes: { orderBy: { createdAt: "asc" } },
      auditLogs: { orderBy: { seq: "desc" }, take: 25, include: { actor: { select: { name: true, email: true } } } },
      _count: { select: { events: true } },
    },
  });

  const staff = await db.user.findMany({ where: { active: true, tenantId: null }, select: { id: true, name: true, email: true, role: true }, orderBy: { name: "asc" } });
  const team = staff.filter((u) => can(u, "cases.view") && !["AUDITOR", "SALES"].includes(u.role)).map((u) => ({ id: u.id, name: u.name ?? u.email, role: roleLabel(u.role) }));
  const clientUsers = kase.tenantId
    ? await db.user.findMany({ where: { active: true, tenantId: kase.tenantId }, select: { id: true, name: true, email: true, role: true } })
    : [];

  const [events, related, evidence, agents] = await Promise.all([
    db.securityEvent.findMany({ where: { caseId: kase.id }, orderBy: { timestamp: "asc" }, take: 50 }),
    user.isClient ? Promise.resolve([]) : findRelatedCases(kase.id),
    gatherEvidence(kase.id),
    Promise.all(
      DISPATCHABLE_AGENTS.map(async (key) => {
        const { profile, provider } = await resolveAgent(key);
        return { key, name: profile.name, description: AGENT_TYPES[key].description, engine: provider ? `${provider.name} (${provider.model})` : "the built-in engine (no model configured)", enabled: profile.enabled && profile.autonomy !== "OFF" };
      }),
    ),
  ]);

  const recommended = user.isClient ? [] : await recommendPlaybooks(kase.id, evidence.entities);
  return { now, kase, team, clientUsers, recommended, events, related, evidence, agents };
}

export default async function CaseDetailPage({ params }: PageProps<"/cases/[id]">) {
  const { id } = await params;
  const user = await pageGuard("cases.view");
  await assertCaseAccess(user, id, "page");
  const { now, kase, team, clientUsers, recommended, events, related, evidence, agents } = await loadCasePage(id, user);

  const ranPlaybookIds = new Set(kase.playbookRuns.map((r) => r.playbookId));
  const suggestions = recommended.filter((p) => !ranPlaybookIds.has(p.id));
  const plan = kase.tenant?.plan ? parsePlan(kase.tenant.plan) : null;
  const watching = kase.watchers.some((w) => w.userId === user.id);
  const closed = CLOSED_STATUSES.includes(kase.status);
  // Shadow-mode analysis stays hidden until the case is closed, so it can't
  // steer the analyst whose call it's measured against.
  const isShadow = (r: { resolution: unknown }) => !!(r.resolution as { shadow?: boolean } | null)?.shadow;
  const shadowHidden = !closed && kase.aiRuns.some(isShadow);
  const latestTriage = kase.aiRuns.find((r) => ["triage", "phishing", "threat_intel"].includes(r.agentKey) && r.status !== "failed" && (closed || !isShadow(r)));
  const triage = latestTriage?.output as TriageOutput | undefined;
  const grounding = latestTriage?.grounding as GroundingReport | undefined;
  const lastFailure = kase.aiRuns[0]?.status === "failed" ? kase.aiRuns[0] : null;

  const canApprove = can(user, "containment.approve");
  const showSoc = !user.isClient;
  const people = [
    ...team,
    ...clientUsers.map((u) => ({ id: u.id, name: u.name ?? u.email, role: `${roleLabel(u.role)} · ${kase.tenant?.name ?? "client"}`, client: true })),
  ];

  const requestable = PROPOSABLE_ACTIONS.map((value) => {
    const pool =
      value === "ISOLATE_HOST" || value === "COLLECT_LOGS" ? evidence.entities.hosts
        : value === "BLOCK_IP" ? evidence.entities.ips
          : value === "DISABLE_USER" ? evidence.entities.users
            : value === "KILL_PROCESS" ? evidence.entities.processes
              : value === "QUARANTINE_FILE" ? evidence.entities.hashes
                : value === "BLOCK_SENDER" ? [...evidence.entities.emails, ...evidence.entities.domains]
                  : evidence.entities.agents;
    return { value, label: ACTION_LABEL[value], targets: pool.filter((t) => matchTarget(value, t, evidence.entities)).slice(0, 25) };
  }).filter((r) => r.targets.length > 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" asChild className="-ml-2">
          <Link href={user.isClient ? "/cases" : CASE_SOURCE_HREF[kase.sourceType]}>
            <ArrowLeft /> {user.isClient ? "Incidents" : CASE_SOURCE_LABEL[kase.sourceType]}
          </Link>
        </Button>
        <div className="flex items-center gap-3">
          <span className="hidden font-mono text-[11px] text-muted-foreground sm:inline">{kase.id}</span>
          <Button variant="outline" size="sm" asChild>
            <a href={`/cases/${kase.id}/pdf`}><Download /> Report PDF</a>
          </Button>
        </div>
      </div>

      <Card className="surface-glow">
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={kase.severity} />
            <StatusBadge status={kase.status} />
            <SlaChip createdAt={kase.createdAt} slaDueAt={kase.slaDueAt} acknowledgedAt={kase.acknowledgedAt} now={now} />
            {showSoc && <TierBadge tier={kase.tier} />}
            <DomainBadge domain={kase.domain} />
            <SourceBadge source={kase.sourceType} />
            {showSoc && <AiStatusBadge status={kase.aiStatus} />}
            {kase.tenant && (
              <Badge variant="outline">
                <Building2 /> {kase.tenant.name}
              </Badge>
            )}
            {kase.tenant?.isTest && <TestBadge />}
            {kase.verdict && <Badge variant="outline" className="capitalize">Verdict: {kase.verdict}</Badge>}
          </div>
          <CardTitle className="mt-2 text-xl leading-snug">{kase.title}</CardTitle>
          {kase.summary && <CardDescription className="whitespace-pre-wrap">{kase.summary}</CardDescription>}
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
          <Meta label="Created">{formatDateTime(kase.createdAt)}</Meta>
          <Meta label="Acknowledged">{kase.acknowledgedAt ? formatDateTime(kase.acknowledgedAt) : kase.slaDueAt ? `due ${formatDateTime(kase.slaDueAt)}` : "—"}</Meta>
          <Meta label="Contained">{kase.containedAt ? formatDateTime(kase.containedAt) : "—"}</Meta>
          <Meta label="Resolved">{kase.resolvedAt ? formatDateTime(kase.resolvedAt) : "—"}</Meta>
          <Meta label="Assignee">{kase.assignedTo ? (kase.assignedTo.name ?? kase.assignedTo.email) : "Unassigned"}</Meta>
          <Meta label="Risk score">{kase.riskScore != null ? Math.round(kase.riskScore) : "—"}</Meta>
          <Meta label="Confidence">{formatPercent(kase.confidence)}</Meta>
          <Meta label="Service plan">{kase.tenant ? plan?.name ?? "None" : "Internal"}</Meta>
        </CardContent>
      </Card>

      {kase.rootCauseNarrative && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Root cause</CardTitle>
          </CardHeader>
          <CardContent className="text-sm whitespace-pre-wrap">{kase.rootCauseNarrative}</CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
          {showSoc && can(user, "ai.view") && (
            <Card className="border-chart-4/25">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base"><Bot className="size-4 text-chart-4" /> AI first response</CardTitle>
                <CardDescription>
                  Initial analysis and containment by an AI agent. A human analyst does the primary analysis — confirm or correct it below.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {triage && latestTriage ? (
                  <div className="flex flex-col gap-3">
                    <div className="grid gap-3 sm:grid-cols-3">
                      <div>
                        <p className="text-xs text-muted-foreground">Verdict</p>
                        <p className={`text-sm font-semibold capitalize ${VERDICT_TONE[triage.verdict] ?? ""}`}>{triage.verdict.replace("_", " ")}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Confidence {grounding && grounding.confidenceAfter < grounding.confidenceBefore ? "(after grounding)" : ""}</p>
                        <div className="mt-1 flex items-center gap-2">
                          <Progress value={Math.round(triage.confidence * 100)} className="h-1.5" />
                          <span className="text-sm font-semibold tabular">{Math.round(triage.confidence * 100)}%</span>
                        </div>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Engine</p>
                        <p className="truncate text-sm" title={latestTriage.model ?? undefined}>
                          {latestTriage.engine}
                          {latestTriage.isLocal && latestTriage.engine !== "built-in" && <Badge variant="soft" className="ml-1">local</Badge>}
                        </p>
                      </div>
                    </div>
                    <p className="text-sm leading-relaxed">{triage.summary}</p>
                    {triage.key_findings.length > 0 && (
                      <ul className="flex flex-col gap-1 text-sm">
                        {triage.key_findings.map((f, i) => (
                          <li key={i} className="flex gap-2">
                            <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-chart-4" />
                            <span>
                              {f.finding} <span className="font-mono text-[11px] text-muted-foreground">{f.evidence.join(", ")}</span>
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {triage.analyst_next_steps.length > 0 && (
                      <div className="rounded-md bg-muted/50 p-3">
                        <p className="text-xs font-medium">For the analyst</p>
                        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-muted-foreground">
                          {triage.analyst_next_steps.map((s, i) => <li key={i}>{s}</li>)}
                        </ul>
                      </div>
                    )}
                    {grounding && grounding.notes.length > 0 && (
                      <p className="text-xs text-muted-foreground">
                        <span className="font-medium text-foreground">Grounding check:</span> {grounding.notes.join("; ")}
                      </p>
                    )}
                    <p className="text-[11px] text-muted-foreground">
                      {AGENT_TYPES[latestTriage.agentKey as keyof typeof AGENT_TYPES]?.name ?? latestTriage.agentKey} · {latestTriage.trigger === "auto" ? "automatic" : "dispatched"} · {formatRelative(latestTriage.createdAt, now)}
                      {latestTriage.durationMs != null && ` · ${(latestTriage.durationMs / 1000).toFixed(1)}s`}
                      {latestTriage.status === "fallback" && " · model call failed, built-in engine used"}
                    </p>
                    {can(user, "ai.feedback") && <AiFeedback runId={latestTriage.id} current={latestTriage.feedback} />}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {shadowHidden
                      ? "This client is in shadow mode: the AI has recorded its analysis, and it's shown here once you close the case, so it can be compared with your call."
                      : kase.aiStatus === "skipped" ? "Below the automatic first-response severity — dispatch an agent if you want one." : "No AI analysis yet."}
                  </p>
                )}
                {lastFailure && <p className="text-xs text-destructive">Last run failed: {lastFailure.error}</p>}
                {can(user, "ai.dispatch") && <AgentDispatch caseId={kase.id} agents={agents.filter((a) => a.enabled)} initialStatus={kase.aiStatus} />}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><ShieldAlert className="size-4" /> Response actions</CardTitle>
              <CardDescription>
                Containment proposed by AI agents or requested by analysts, gated by the response policy. Everything here is reversible and audited.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ResponseActions
                caseId={kase.id}
                now={now.toISOString()}
                canApprove={canApprove}
                canRequest={can(user, "containment.request")}
                requestable={requestable}
                actions={kase.responseActions.filter((a) => a.status !== "SHADOW" || (closed && showSoc)).map((a) => {
                  const result = (a.result ?? null) as { summary?: string; manual?: { by?: string } } | null;
                  return {
                    id: a.id,
                    actionType: a.actionType,
                    label: ACTION_LABEL[a.actionType],
                    target: a.target,
                    source: a.source,
                    status: a.status,
                    rationale: a.rationale,
                    policyReason: a.policyReason,
                    confidence: a.confidence,
                    summary: result?.summary ?? null,
                    manualBy: result?.manual?.by ?? null,
                    rollbackable: !!ROLLBACK_OF[a.actionType],
                    createdAt: a.createdAt.toISOString(),
                    requiredApprovals: a.requiredApprovals,
                    approvedBy: approvalsOf(a.approvals).map((x) => x.name),
                    policyVersion: a.policyVersion,
                    trace: Array.isArray(a.trace) ? (a.trace as Array<{ layer: string; reason: string }>).map((t) => ({ layer: String(t.layer), reason: String(t.reason) })) : [],
                  };
                })}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Users className="size-4" /> Discussion</CardTitle>
              <CardDescription>
                {user.isClient ? "Updates from your SOC team. Reply here to reach them." : "Analyst collaboration. Internal by default; toggle to post a client-visible update."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Discussion
                caseId={kase.id}
                now={now.toISOString()}
                isClient={user.isClient}
                canComment={can(user, "cases.comment")}
                canPublish={can(user, "cases.share")}
                people={people.filter((p) => p.id !== user.id)}
                comments={kase.comments.map((c) => ({ id: c.id, authorName: c.authorName, authorId: c.authorId, kind: c.kind, body: c.body, internal: c.internal, createdAt: c.createdAt.toISOString() }))}
              />
            </CardContent>
          </Card>

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
                      {showSoc && (
                        <details className="mt-1">
                          <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Evidence · rule {d.ruleId}</summary>
                          <JsonView value={d.evidence} className="mt-2" />
                        </details>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Timeline</CardTitle>
              <CardDescription>Telemetry, detections, AI and analyst actions, in order.</CardDescription>
            </CardHeader>
            <CardContent>
              <CaseTimeline entries={kase.timeline} />
            </CardContent>
          </Card>

          {showSoc && events.length > 0 && (
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

          {showSoc && <SourcePanel kase={kase} />}
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          {showSoc && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Triage</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                <TriagePanel
                  caseId={kase.id}
                  status={kase.status}
                  disposition={kase.disposition ? { value: kase.disposition, label: dispositionLabel(kase.disposition), reason: kase.dispositionReason } : null}
                  aiScore={closed && kase.aiOutcomes.length ? { agreed: kase.aiOutcomes.filter((o) => o.agreed).length, total: kase.aiOutcomes.length, falseContainments: kase.aiOutcomes.filter((o) => o.falseContainment).length, misses: kase.aiOutcomes.filter((o) => o.aiOutcome === "NONE").length } : null}
                  severity={kase.severity}
                  assigneeId={kase.assignedToId}
                  acknowledged={!!kase.acknowledgedAt}
                  watching={watching}
                  viewerId={user.id}
                  canTriage={can(user, "cases.triage")}
                  canAssignOthers={can(user, "cases.assign")}
                  team={team}
                />
                <CollabActions
                  caseId={kase.id}
                  tier={kase.tier}
                  team={team.filter((m) => m.id !== user.id)}
                  hasClient={!!kase.tenantId}
                  canEscalate={can(user, "cases.escalate")}
                  canShare={can(user, "cases.share")}
                  canAssignOthers={can(user, "cases.assign")}
                />
                {kase.watchers.length > 0 && (
                  <div>
                    <p className="flex items-center gap-1 text-xs text-muted-foreground"><Eye className="size-3.5" /> Watching</p>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {kase.watchers.map((w) => (
                        <Badge key={w.userId} variant="soft">{w.user.name ?? w.user.email}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {kase.slaDueAt && plan && (
                  <p className="text-xs text-muted-foreground">
                    {plan.name} SLA: acknowledge {kase.severity.toLowerCase()} cases within {formatMinutes(plan.ackMinutes[kase.severity])}
                    {plan.containMinutes[kase.severity] ? `, contain within ${formatMinutes(plan.containMinutes[kase.severity])}` : ""}.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

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
                        {can(user, "intel.view") && <RecheckButton indicatorId={indicator.id} />}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          {showSoc && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base"><Link2 className="size-4" /> Related cases ({related.length})</CardTitle>
                <CardDescription>Earlier or concurrent cases sharing indicators, hosts, accounts, or the same agent.</CardDescription>
              </CardHeader>
              <CardContent>
                {related.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No other case shares evidence with this one.</p>
                ) : (
                  <ul className="flex flex-col gap-3">
                    {related.map((r) => (
                      <li key={r.id} className="text-sm">
                        <div className="flex items-start justify-between gap-2">
                          <Link href={`/cases/${r.id}`} className="line-clamp-2 font-medium hover:underline">{r.title}</Link>
                          <SeverityBadge severity={r.severity} />
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {CASE_SOURCE_LABEL[r.sourceType]} · {formatRelative(r.createdAt, now)}{r.verdict ? ` · ${r.verdict}` : ""}
                        </p>
                        <p className="mt-0.5 text-xs text-muted-foreground">{r.reasons.slice(0, 3).join(" · ")}{r.reasons.length > 3 ? ` +${r.reasons.length - 3}` : ""}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          )}

          {showSoc && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base"><Workflow className="size-4" /> Response playbooks</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {kase.playbookRuns.length === 0 && suggestions.length === 0 && (
                  <p className="text-sm text-muted-foreground">No playbook fits this case.</p>
                )}
                {kase.playbookRuns.map((run) => (
                  <div key={run.id} className="rounded-md border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-sm font-medium">{run.playbook.name}</p>
                      {run.status === "SUCCEEDED" && Array.isArray(run.results) && (run.results as Array<{ status?: string }>).some((r) => r.status === "manual") ? (
                        <Badge variant="warning">steps to do by hand</Badge>
                      ) : (
                        <Badge variant={EXECUTION_VARIANT[run.status]}>{run.status.replaceAll("_", " ").toLowerCase()}</Badge>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {run.triggeredBy} · {formatRelative(run.startedAt, now)}
                      {run.approvals.map((a) => ` · ${a.decision} by ${a.approver.name ?? a.approver.email}`).join("")}
                    </p>
                    {run.error && <p className="mt-1 text-xs text-destructive">{run.error}</p>}
                    {Array.isArray(run.results) && run.results.length > 0 && (
                      <ul className="mt-2 space-y-0.5 text-xs">
                        {(run.results as Array<{ action: string; summary: string; status: string }>).map((r, i) => (
                          <li key={i} className={r.status === "failed" ? "text-destructive" : undefined}>
                            <span className="font-medium">{r.action}</span>: {r.summary}
                            {r.status === "manual" && <span className="text-warning-ink"> (do by hand)</span>}
                          </li>
                        ))}
                      </ul>
                    )}
                    {run.status === "PENDING_APPROVAL" && (
                      <div className="mt-3">
                        <ExecutionDecision executionId={run.id} canApprove={canApprove} />
                      </div>
                    )}
                  </div>
                ))}
                {suggestions.length > 0 && (
                  <div className="flex flex-col gap-2">
                    <p className="text-xs font-medium text-muted-foreground">Recommended, not yet run</p>
                    {suggestions.map((p) => (
                      <div key={p.id} className="flex flex-col gap-1 rounded-md border p-2.5">
                        <div className="flex items-center justify-between gap-2 text-sm">
                          <span className="min-w-0 truncate font-medium">{p.name}</span>
                          {can(user, "containment.request") && <RunPlaybookButton caseId={kase.id} playbookId={p.id} />}
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {p.exactMatch && <Badge variant="info" className="mr-1.5">trigger match</Badge>}
                          {p.reasons.filter((r) => r !== "Its trigger matches this case").join(" · ")}
                        </p>
                        {p.noTarget.length > 0 && <p className="text-[11px] text-warning-ink">Nothing in the evidence for: {p.noTarget.join(", ")}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {showSoc && (
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
                        {log.actor ? (log.actor.name ?? log.actor.email) : "system"} · {formatRelative(log.createdAt, now)}
                      </span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-xs text-muted-foreground">{label}</p>
      <div className="mt-0.5 truncate">{children}</div>
    </div>
  );
}
