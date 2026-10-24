import Link from "next/link";
import { Activity, Bot, Inbox, Radar, ShieldAlert, Timer, Workflow } from "lucide-react";
import type { CaseSeverity, CaseSource, Prisma, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { pageGuard, type SessionUser } from "@/lib/session";
import { caseScope, selectedTenantId } from "@/lib/access";
import { can, DOMAIN_LABEL, SECURITY_DOMAINS } from "@/lib/rbac";
import { caseWhere, type CaseQueue } from "@/lib/cases/service";
import { CASE_SOURCES, CASE_SOURCE_LABEL, CLOSED_STATUSES } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge, SourceBadge, StatusBadge } from "@/components/shared/case-badges";
import { AiStatusBadge, DomainBadge, SlaChip, TierBadge } from "@/components/shared/case-chips";
import { EmptyState } from "@/components/shared/empty-state";
import { Pagination, parsePage } from "@/components/shared/pagination";
import { SimulationPanel } from "@/components/cases/simulation-panel";
import { IngestPanel } from "@/components/cases/ingest-panel";

const PAGE_SIZE = 25;

const QUEUES: Array<{ key: CaseQueue | "all"; label: string; staffOnly?: boolean }> = [
  { key: "all", label: "All" },
  { key: "mine", label: "My cases", staffOnly: true },
  { key: "unassigned", label: "Unassigned", staffOnly: true },
  { key: "ai", label: "AI triaged · awaiting analyst", staffOnly: true },
  { key: "sla", label: "SLA due / breached", staffOnly: true },
  { key: "approval", label: "Awaiting approval" },
  { key: "tier3", label: "Tier 3", staffOnly: true },
];

function one(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

async function getStreamStats(scope: Prisma.CaseWhereInput, user: SessionUser) {
  const now = new Date();
  const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const tenant = user.isClient ? user.tenantId : await selectedTenantId(user);
  const eventScope = tenant ? { tenantId: tenant } : {};
  const [openCount, detections24h, events24h, awaiting, slaRisk] = await Promise.all([
    db.case.count({ where: { AND: [scope, { status: { notIn: CLOSED_STATUSES } }] } }),
    db.detection.count({ where: { createdAt: { gte: since }, case: scope } }),
    db.securityEvent.count({ where: { ingestedAt: { gte: since }, ...eventScope } }),
    db.case.count({ where: { AND: [scope, { status: "AWAITING_APPROVAL" }] } }),
    db.case.count({ where: { AND: [scope, caseWhere({ queue: "sla", now }), { status: { notIn: CLOSED_STATUSES } }] } }),
  ]);
  return { openCount, detections24h, events24h, awaiting, slaRisk, now };
}

export default async function CasesPage({ searchParams }: PageProps<"/cases">) {
  const user = await pageGuard("cases.view");
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const source = CASE_SOURCES.includes(one(sp.source) as CaseSource) ? (one(sp.source) as CaseSource) : undefined;
  const severity = SEVERITY_ORDER.includes(one(sp.severity) as CaseSeverity) ? (one(sp.severity) as CaseSeverity) : undefined;
  const domain = SECURITY_DOMAINS.includes(one(sp.domain) as SecurityDomain) ? (one(sp.domain) as SecurityDomain) : undefined;
  const queueParam = one(sp.queue);
  const queue = QUEUES.find((q) => q.key === queueParam && q.key !== "all" && (!q.staffOnly || !user.isClient))?.key as CaseQueue | undefined;
  const statusParam = one(sp.status);
  const status = statusParam === "closed" || statusParam === "all" ? statusParam : "open";
  const q = one(sp.q)?.trim() || undefined;
  const technique = /^T\d{4}(\.\d{3})?$/.test(one(sp.technique) ?? "") ? one(sp.technique) : undefined;

  const scope = await caseScope(user);
  const stats = await getStreamStats(scope, user);
  const where: Prisma.CaseWhereInput = { AND: [scope, caseWhere({ sourceType: source, severity, status, q, technique, domain, queue, viewerId: user.id, now: stats.now })] };

  const [cases, total, tenantId] = await Promise.all([
    db.case.findMany({
      where,
      orderBy: queue === "sla" ? [{ slaDueAt: "asc" }] : [{ createdAt: "desc" }],
      skip: (page - 1) * PAGE_SIZE,
      take: PAGE_SIZE,
      include: {
        tenant: { select: { name: true } },
        assignedTo: { select: { name: true, email: true } },
        _count: { select: { detections: true } },
      },
    }),
    db.case.count({ where }),
    user.isClient ? Promise.resolve(user.tenantId) : selectedTenantId(user),
  ]);
  const tenantName = tenantId ? (await db.tenant.findUnique({ where: { id: tenantId }, select: { name: true } }))?.name ?? null : null;
  const queueHref = (key: string) => {
    const params = new URLSearchParams();
    if (key !== "all") params.set("queue", key);
    if (domain) params.set("domain", domain);
    const qs = params.toString();
    return `/cases${qs ? `?${qs}` : ""}`;
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label={user.isClient ? "Open incidents" : "Open cases"} value={stats.openCount} icon={ShieldAlert} />
        <StatTile label="SLA due / breached" value={stats.slaRisk} icon={Timer} tone={stats.slaRisk > 0 ? "critical" : "default"} />
        <StatTile label="Awaiting approval" value={stats.awaiting} icon={Workflow} tone={stats.awaiting > 0 ? "warning" : "default"} />
        <StatTile label="Detections (24h)" value={stats.detections24h} icon={Radar} />
        <StatTile label="Events ingested (24h)" value={stats.events24h} icon={Activity} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{user.isClient ? "Your incidents" : "Case queue"}</CardTitle>
          <CardDescription>
            {user.isClient
              ? "Everything your SOC is working on for your organization."
              : `Every case from every module and onboarded tool${user.domains.length && !can(user, "cases.view_all") ? ` — scoped to your queues: ${user.domains.map((d) => DOMAIN_LABEL[d]).join(", ")}` : ""}.`}
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <nav className="flex flex-wrap gap-1.5" aria-label="Queues">
            {QUEUES.filter((qq) => !qq.staffOnly || !user.isClient).map((qq) => {
              const active = (queue ?? "all") === qq.key;
              return (
                <Link
                  key={qq.key}
                  href={queueHref(qq.key)}
                  className={cn(
                    "flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors hover:bg-accent",
                    active && "border-primary bg-primary text-primary-foreground hover:bg-primary/90",
                  )}
                >
                  {qq.key === "ai" && <Bot className="size-3" />}
                  {qq.label}
                </Link>
              );
            })}
          </nav>

          <form className="flex flex-wrap items-end gap-2" action="/cases">
            {queue && <input type="hidden" name="queue" value={queue} />}
            <Input name="q" defaultValue={q} placeholder="Search title, summary, entity…" className="w-64" />
            {!user.isClient && (
              <NativeSelect name="domain" defaultValue={domain ?? ""} aria-label="Security domain">
                <option value="">All domains</option>
                {SECURITY_DOMAINS.map((d) => (
                  <option key={d} value={d}>{DOMAIN_LABEL[d]}</option>
                ))}
              </NativeSelect>
            )}
            <NativeSelect name="source" defaultValue={source ?? ""} aria-label="Source">
              <option value="">All sources</option>
              {CASE_SOURCES.map((s) => (
                <option key={s} value={s}>{CASE_SOURCE_LABEL[s]}</option>
              ))}
            </NativeSelect>
            <NativeSelect name="severity" defaultValue={severity ?? ""} aria-label="Severity">
              <option value="">Any severity</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
              ))}
            </NativeSelect>
            <NativeSelect name="status" defaultValue={status} aria-label="Status">
              <option value="open">Open</option>
              <option value="closed">Closed</option>
              <option value="all">All</option>
            </NativeSelect>
            {technique && <input type="hidden" name="technique" value={technique} />}
            <Button type="submit" variant="secondary">Filter</Button>
            {technique && <span className="rounded-md border px-2 py-1 font-mono text-xs">technique {technique}</span>}
            {(q || source || severity || technique || domain || queue || status !== "open") && (
              <Button variant="ghost" asChild>
                <Link href="/cases">Reset</Link>
              </Button>
            )}
          </form>

          {cases.length === 0 ? (
            <EmptyState
              icon={Inbox}
              title="Nothing in this queue"
              description={can(user, "simulation.run") ? "Run an attack simulation or ingest telemetry below to generate detections." : "New cases appear here as soon as they are opened."}
            />
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">Severity</TableHead>
                      <TableHead>Case</TableHead>
                      {!user.isClient && <TableHead>Client</TableHead>}
                      <TableHead>Queue</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>SLA</TableHead>
                      {!user.isClient && <TableHead>Assignee</TableHead>}
                      <TableHead className="text-right">Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {cases.map((c) => (
                      <TableRow key={c.id}>
                        <TableCell><SeverityBadge severity={c.severity} /></TableCell>
                        <TableCell className="max-w-md">
                          <Link href={`/cases/${c.id}`} className="line-clamp-1 font-medium hover:underline">
                            {c.title}
                          </Link>
                          <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                            <SourceBadge source={c.sourceType} />
                            {!user.isClient && <AiStatusBadge status={c.aiStatus} />}
                            {c.verdict && <span className="text-xs capitalize text-muted-foreground">{c.verdict}</span>}
                            <span className="text-xs text-muted-foreground">{c._count.detections} detection{c._count.detections === 1 ? "" : "s"}</span>
                          </div>
                        </TableCell>
                        {!user.isClient && <TableCell className="text-xs">{c.tenant?.name ?? <span className="text-muted-foreground">Internal</span>}</TableCell>}
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            <DomainBadge domain={c.domain} />
                            {!user.isClient && <TierBadge tier={c.tier} />}
                          </div>
                        </TableCell>
                        <TableCell><StatusBadge status={c.status} /></TableCell>
                        <TableCell><SlaChip createdAt={c.createdAt} slaDueAt={c.slaDueAt} acknowledgedAt={c.acknowledgedAt} now={stats.now} /></TableCell>
                        {!user.isClient && (
                          <TableCell className="text-xs">{c.assignedTo ? (c.assignedTo.name ?? c.assignedTo.email) : <span className="text-muted-foreground">—</span>}</TableCell>
                        )}
                        <TableCell className="text-right text-xs text-muted-foreground" title={c.createdAt.toISOString()}>
                          {formatRelative(c.createdAt, stats.now)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <Pagination
                page={page}
                pageSize={PAGE_SIZE}
                total={total}
                basePath="/cases"
                params={{ q, source, severity, technique, domain, queue, status: status === "open" ? undefined : status }}
              />
            </>
          )}
        </CardContent>
      </Card>

      {can(user, "simulation.run") && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <SimulationPanel tenantId={tenantId} tenantName={tenantName} />
          <IngestPanel tenantId={tenantId} tenantName={tenantName} />
        </div>
      )}
    </div>
  );
}
