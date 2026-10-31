import Link from "next/link";
import { CheckCircle2, Inbox } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { caseScope } from "@/lib/access";
import { can } from "@/lib/rbac";
import { formatDateTime, formatRelative } from "@/lib/format";
import { ACTION_LABEL } from "@/lib/response/executor";
import { approvalsOf } from "@/lib/response/service";
import { NOTICE_LABEL, clockOf, formatSpan } from "@/lib/compliance/notices";
import { KIND_LABEL } from "@/lib/changes/rules";
import { ActionDecision } from "@/components/approvals/action-decision";
import { ExecutionDecision } from "@/components/playbooks/execution-decision";
import { EmptyState } from "@/components/shared/empty-state";
import { TestBadge } from "@/components/shared/test-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

// Everything waiting on someone's yes, in one place: containment the policy
// held, playbooks that need approval, regulatory notices with the client,
// and rule changes waiting for approval. Each links to where it's decided;
// containment can be decided right here.
export default async function ApprovalsPage() {
  const user = await pageGuard("containment.approve");
  const now = new Date();
  const scope = await caseScope(user);
  const tenantWhere = user.isClient ? { tenantId: user.tenantId ?? "__none__" } : {};

  const [actions, playbooks, notices, rulebooks] = await Promise.all([
    db.responseAction.findMany({
      where: { status: "PENDING_APPROVAL", case: scope },
      include: { case: { select: { id: true, title: true, severity: true, tenant: { select: { name: true, isTest: true } } } } },
      orderBy: { createdAt: "asc" },
      take: 100,
    }),
    db.playbookExecution.findMany({
      where: { status: "PENDING_APPROVAL", case: scope },
      include: { playbook: { select: { name: true } }, case: { select: { id: true, title: true, tenant: { select: { name: true } } } } },
      orderBy: { startedAt: "asc" },
      take: 100,
    }),
    can(user, "compliance.view")
      ? db.regulatoryNotice.findMany({ where: { ...tenantWhere, status: "AWAITING_APPROVAL" }, include: { case: { select: { id: true, title: true } }, tenant: { select: { name: true } } }, orderBy: { dueAt: { sort: "asc", nulls: "last" } } })
      : Promise.resolve([]),
    can(user, "rulebook.view") ? db.ruleChange.findMany({ where: { ...(user.isClient ? tenantWhere : can(user, "ai.configure") ? {} : { tenantId: { not: null } }), status: "PENDING" }, include: { tenant: { select: { id: true, name: true } } }, orderBy: { createdAt: "asc" } }) : Promise.resolve([]),
  ]);
  const total = actions.length + playbooks.length + notices.length + rulebooks.length;
  const client = user.isClient;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <p className="flex items-center gap-2 text-sm text-muted-foreground"><Inbox className="size-4" /> {total} waiting</p>
        <h2 className="text-xl font-semibold tracking-tight">Approvals</h2>
      </div>

      {total === 0 && (
        <Card>
          <CardContent>
            <EmptyState icon={CheckCircle2} title="Nothing is waiting for approval" description="Containment the policy holds, playbooks that need a yes, regulatory notices for you to approve and rule changes to approve all show up here." />
          </CardContent>
        </Card>
      )}

      {actions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Containment</CardTitle>
            <CardDescription>Held by the response policy until someone approves. Nothing runs while it waits; the client&apos;s approver chain is being asked in turn.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col divide-y">
            {actions.map((a) => {
              const approved = approvalsOf(a.approvals).map((x) => x.name);
              return (
                <div key={a.id} className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">
                      {ACTION_LABEL[a.actionType]} <span className="font-mono text-xs">{a.target}</span>
                      <Badge variant="outline" className="ml-2">{a.source === "ai" ? "proposed by AI" : "requested by an analyst"}</Badge>
                    </p>
                    <p className="text-xs text-muted-foreground">
                      <Link href={`/cases/${a.case.id}`} className="hover:underline">{a.case.title}</Link>
                      {!client && a.case.tenant && <> · {a.case.tenant.name}{a.case.tenant.isTest && <TestBadge className="ml-1" />}</>} · {a.case.severity.toLowerCase()} · waiting {formatRelative(a.createdAt, now)}
                    </p>
                    {a.rationale && <p className="mt-1 text-xs">{a.rationale}</p>}
                    {a.policyReason && <p className="mt-0.5 text-xs text-muted-foreground">Why it&apos;s held: {a.policyReason}</p>}
                    {a.requiredApprovals > 1 && <p className="mt-0.5 text-xs text-muted-foreground">Needs {a.requiredApprovals} different approvers{approved.length ? `; approved so far by ${approved.join(", ")}` : ""}.</p>}
                  </div>
                  <ActionDecision actionId={a.id} />
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      {playbooks.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Playbooks</CardTitle>
            <CardDescription>Response playbooks that matched a case and need approval before they run.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col divide-y">
            {playbooks.map((p) => (
              <div key={p.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium">{p.playbook.name}</p>
                  <p className="text-xs text-muted-foreground"><Link href={`/cases/${p.case.id}`} className="hover:underline">{p.case.title}</Link>{!client && p.case.tenant ? ` · ${p.case.tenant.name}` : ""} · waiting {formatRelative(p.startedAt, now)}</p>
                </div>
                <ExecutionDecision executionId={p.id} canApprove />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {notices.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Regulatory notices</CardTitle>
            <CardDescription>{client ? "Reports your SOC has drafted for you to approve before they're filed." : "Drafted and waiting for the client's approval."}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col divide-y">
            {notices.map((n) => {
              const c = clockOf(n, now);
              return (
                <div key={n.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{NOTICE_LABEL[n.kind]}{n.sequence > 1 ? ` · update ${n.sequence - 1}` : ""}</p>
                    <p className="text-xs text-muted-foreground">
                      {n.case.title}{!client ? ` · ${n.tenant.name}` : ""}
                      {n.dueAt ? ` · due ${formatDateTime(n.dueAt)} (${c.state === "overdue" ? `overdue by ${formatSpan(-(c.marginMs ?? 0))}` : `${formatSpan(c.marginMs ?? 0)} left`})` : ""}
                    </p>
                  </div>
                  <Button size="sm" variant={client ? "default" : "outline"} asChild><Link href={`/cases/${n.case.id}#regulatory`}>{client ? "Review and approve" : "Open"}</Link></Button>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}

      {rulebooks.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Rule changes to approve</CardTitle>
            <CardDescription>Changes to the rules containment runs under. Each takes effect only once the client and HELIOS have both approved it (platform changes: a second HELIOS approver).</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col divide-y">
            {rulebooks.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium break-words">{client || !r.tenant ? r.summary : `${r.tenant.name} · ${r.summary}`}</p>
                  <p className="text-xs text-muted-foreground">
                    {KIND_LABEL[r.kind]} · asked by {r.requestedByName} {formatRelative(r.createdAt, now)} · {r.clientApprovedAt || !r.tenantId ? "" : "client's approval waiting · "}{r.heliosApprovedAt ? "HELIOS approved" : "HELIOS's approval waiting"}
                  </p>
                </div>
                <Button size="sm" variant="outline" asChild><Link href={r.tenantId ? "/changes" : "/changes?scope=platform"}>Review</Link></Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
