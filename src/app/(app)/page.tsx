import Link from "next/link";
import { AlarmClock, Bot, Building2, CircleCheck, Clock, FileText, Inbox, Laptop, Plug, ShieldAlert, ShieldCheck, Siren, Target, Timer, TrendingUp, UserX, Workflow } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard, type SessionUser } from "@/lib/session";
import { can, DOMAIN_LABEL } from "@/lib/rbac";
import { caseScope, tenantScope } from "@/lib/access";
import { loadCommercialDashboard, loadOperationsDashboard } from "@/lib/dashboard";
import { formatDuration } from "@/lib/metrics";
import { formatMinutes, parsePlan } from "@/lib/plans";
import { AUTONOMY_LABEL } from "@/lib/ai/catalog";
import { aiSettings } from "@/lib/settings";
import { setupChecklist } from "@/lib/setup";
import { formatMoney, type QuoteResult } from "@/lib/pricing/calculator";
import { CASE_SOURCE_LABEL, CASE_STATUS_LABEL } from "@/lib/cases/labels";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { SeverityBarChart } from "@/components/dashboard/severity-bar-chart";
import { CaseVolumeChart } from "@/components/dashboard/case-volume-chart";
import { FirstResponseBar } from "@/components/dashboard/first-response-bar";
import { BarList } from "@/components/dashboard/bar-list";
import { LiveRefresh } from "@/components/dashboard/live-refresh";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge, StatusBadge } from "@/components/shared/case-badges";
import { AiStatusBadge, SlaChip } from "@/components/shared/case-chips";

function greeting(now: Date) {
  const h = now.getUTCHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

export default async function OverviewPage() {
  const user = await pageGuard("dashboard.view");
  if (!can(user, "cases.view")) return <CommercialOverview user={user} />;
  return user.isClient ? <ClientOverview user={user} /> : <SocOverview user={user} />;
}

async function SocOverview({ user }: { user: SessionUser }) {
  const [d, settings, setup] = await Promise.all([
    loadOperationsDashboard(await caseScope(user), await tenantScope(user), user.id),
    aiSettings(),
    user.role === "ADMIN" ? setupChecklist() : Promise.resolve(null),
  ]);
  const setupLeft = setup?.filter((s) => !s.done) ?? [];
  const attention = d.slaDue + d.awaiting + d.unassignedCritical;
  const sla = d.metrics.slaCompliance;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-sm text-muted-foreground">{greeting(d.now)}, {user.name?.split(" ")[0] ?? "analyst"}</p>
          <h2 className="text-xl font-semibold tracking-tight">Security operations</h2>
        </div>
        <div className="flex items-center gap-2">
          {settings.killSwitch && <Badge variant="destructive">AI kill switch on</Badge>}
          <LiveRefresh />
        </div>
      </div>

      {setup && setupLeft.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Get HELIOS ready · {setup.length - setupLeft.length} of {setup.length} done</CardTitle>
            <CardDescription>Everything here is your own business data, so nothing comes pre-filled. Quotes, SLAs and AI agents use it as soon as it&apos;s set.</CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="grid gap-2 sm:grid-cols-2">
              {setup.map((s) => (
                <li key={s.key}>
                  <Link href={s.href} className={cn("flex items-start gap-2 rounded-lg border p-3 hover:bg-accent", s.done && "opacity-60")}>
                    <CircleCheck className={cn("mt-0.5 size-4 shrink-0", s.done ? "text-success-ink" : "text-muted-foreground/40")} aria-label={s.done ? "Done" : "To do"} />
                    <span>
                      <span className="block text-sm font-medium">{s.label}</span>
                      <span className="block text-xs text-muted-foreground">{s.detail}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      <Card className="surface-glow">
        <CardContent className="flex flex-wrap items-center justify-between gap-6 py-2">
          <div>
            <p className="text-sm text-muted-foreground">Needs attention now</p>
            <p className={cn("text-5xl font-semibold tracking-tight", attention > 0 && "text-destructive")}>{attention}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link href="/cases?queue=sla" className="flex items-center gap-2 rounded-lg border bg-background/60 px-3 py-2 text-sm hover:bg-accent">
              <AlarmClock className="size-4 text-destructive" /> <span className="font-semibold tabular">{d.slaDue}</span> SLA due or breached
            </Link>
            <Link href="/cases?queue=approval" className="flex items-center gap-2 rounded-lg border bg-background/60 px-3 py-2 text-sm hover:bg-accent">
              <Workflow className="size-4 text-warning-ink" /> <span className="font-semibold tabular">{d.awaiting}</span> awaiting approval
            </Link>
            <Link href="/cases?queue=unassigned&severity=CRITICAL" className="flex items-center gap-2 rounded-lg border bg-background/60 px-3 py-2 text-sm hover:bg-accent">
              <UserX className="size-4 text-muted-foreground" /> <span className="font-semibold tabular">{d.unassignedCritical}</span> unassigned critical/high
            </Link>
            <Link href="/cases?queue=mine" className="flex items-center gap-2 rounded-lg border bg-background/60 px-3 py-2 text-sm hover:bg-accent">
              <Inbox className="size-4 text-muted-foreground" /> <span className="font-semibold tabular">{d.mine.length}</span> assigned to me
            </Link>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <StatTile label="Open cases" value={d.openCount} icon={ShieldAlert} />
        <StatTile label="Critical open" value={d.criticalOpen} icon={Siren} tone={d.criticalOpen > 0 ? "critical" : "default"} />
        <StatTile label="SLA met (30d)" value={sla == null ? "—" : `${Math.round(sla * 100)}%`} icon={Timer} tone={sla != null && sla < 0.9 ? "warning" : "default"} hint={`${d.metrics.slaBreached} breached`} />
        <StatTile label="Mean time to ack" value={formatDuration(d.metrics.mttaMinutes)} icon={Clock} hint={`contain ${formatDuration(d.metrics.mttcMinutes)}`} />
        <StatTile label="AI runs (30d)" value={d.ai.runs} icon={Bot} hint={d.ai.agreement == null ? "no analyst feedback yet" : `${Math.round(d.ai.agreement * 100)}% analyst agreement`} />
        <StatTile label="Endpoint protection" value={d.endpoints.avgScore == null ? "—" : d.endpoints.avgScore} icon={Laptop} hint={`${d.endpoints.gaps} with essential gaps`} tone={d.endpoints.gaps > 0 ? "warning" : "default"} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">New cases, last 14 days</CardTitle>
            <CardDescription>Critical and high severity highlighted.</CardDescription>
          </CardHeader>
          <CardContent>
            <CaseVolumeChart days={d.trend} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Bot className="size-4" /> First response (30d)</CardTitle>
            <CardDescription>Who picked up each new case first. {d.ai.autoExecuted} containment action{d.ai.autoExecuted === 1 ? "" : "s"} run by AI.</CardDescription>
          </CardHeader>
          <CardContent>
            <FirstResponseBar {...d.ai.firstResponse} />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Open by severity</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityBarChart counts={d.severityCounts} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Building2 className="size-4" /> Open by client</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList items={d.byTenant.map((t) => ({ label: t.name, value: t.count }))} emptyText="No open cases." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Open by queue</CardTitle>
          </CardHeader>
          <CardContent>
            <BarList items={d.byDomain.map((q) => ({ label: q.domain ? DOMAIN_LABEL[q.domain] : "Unrouted", value: q.count, href: q.domain ? `/cases?domain=${q.domain}` : undefined }))} emptyText="No open cases." />
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader className="flex flex-row items-start justify-between gap-2">
            <div>
              <CardTitle className="text-base">Live case feed</CardTitle>
              <CardDescription>Newest first, across every module and onboarded tool.</CardDescription>
            </div>
            <Button variant="outline" size="sm" asChild><Link href="/cases">Open queue</Link></Button>
          </CardHeader>
          <CardContent>
            {d.recent.length === 0 ? (
              <p className="text-sm text-muted-foreground">No cases yet — they open when an onboarded tool sends an alert or uploaded logs trip a detection.</p>
            ) : (
              <ul className="divide-y">
                {d.recent.map((c) => (
                  <li key={c.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <Link href={`/cases/${c.id}`} className="block truncate text-sm font-medium hover:underline">{c.title}</Link>
                      <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                        {c.tenant?.name ?? "Internal"} · {CASE_SOURCE_LABEL[c.sourceType]} · {formatRelative(c.createdAt, d.now)}
                        <AiStatusBadge status={c.aiStatus} />
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <SlaChip createdAt={c.createdAt} slaDueAt={c.slaDueAt} acknowledgedAt={c.acknowledgedAt} now={d.now} className="hidden sm:inline-flex" />
                      <SeverityBadge severity={c.severity} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <div className="flex flex-col gap-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">My queue</CardTitle>
            </CardHeader>
            <CardContent>
              {d.mine.length === 0 ? (
                <p className="text-sm text-muted-foreground">Nothing assigned to you.</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {d.mine.map((c) => (
                    <li key={c.id} className="flex items-center justify-between gap-2">
                      <Link href={`/cases/${c.id}`} className="min-w-0 truncate text-sm hover:underline">{c.title}</Link>
                      <div className="flex shrink-0 items-center gap-1">
                        <SlaChip createdAt={c.createdAt} slaDueAt={c.slaDueAt} acknowledgedAt={c.acknowledgedAt} now={d.now} />
                        <StatusBadge status={c.status} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="size-4" /> Essential controls</CardTitle>
              <CardDescription>{d.endpoints.total} endpoints · {d.endpoints.isolated} isolated</CardDescription>
            </CardHeader>
            <CardContent>
              <BarList items={d.endpoints.controls.map((c) => ({ label: c.label, value: c.pct, href: "/endpoints" }))} unit="%" emptyText="No endpoints yet." />
            </CardContent>
          </Card>
          {can(user, "integrations.view") && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base"><Plug className="size-4" /> Tool health</CardTitle>
              </CardHeader>
              <CardContent>
                {d.integrations.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No tools onboarded yet.</p>
                ) : (
                  <ul className="flex flex-col gap-1.5 text-sm">
                    {d.integrations.map((i) => (
                      <li key={i.id} className="flex items-center justify-between gap-2">
                        <span className="min-w-0 truncate">{i.name}<span className="text-xs text-muted-foreground"> · {i.tenant?.name ?? "SOC"}</span></span>
                        <Badge variant={!i.enabled ? "outline" : i.status === "CONNECTED" ? "success" : i.status === "DEGRADED" ? "warning" : "soft"}>
                          {!i.enabled ? "off" : i.lastEventAt ? formatRelative(i.lastEventAt, d.now) : i.status.toLowerCase()}
                        </Badge>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

async function ClientOverview({ user }: { user: SessionUser }) {
  const tenantId = user.tenantId!;
  const [d, tenant, pending] = await Promise.all([
    loadOperationsDashboard(await caseScope(user), await tenantScope(user), user.id),
    db.tenant.findUniqueOrThrow({ where: { id: tenantId }, include: { plan: true } }),
    db.responseAction.findMany({ where: { tenantId, status: "PENDING_APPROVAL" }, include: { case: { select: { id: true, title: true } } }, take: 5 }),
  ]);
  const plan = tenant.plan ? parsePlan(tenant.plan) : null;
  const sla = d.metrics.slaCompliance;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-sm text-muted-foreground">{tenant.name}{plan ? ` · ${plan.name}` : ""}</p>
          <h2 className="text-xl font-semibold tracking-tight">Your security at a glance</h2>
        </div>
        <LiveRefresh seconds={60} />
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="Open incidents" value={d.openCount} icon={ShieldAlert} tone={d.criticalOpen > 0 ? "critical" : "default"} hint={`${d.criticalOpen} critical`} />
        <StatTile label="SLA met (30d)" value={sla == null ? "—" : `${Math.round(sla * 100)}%`} icon={Target} />
        <StatTile label="Time to acknowledge" value={formatDuration(d.metrics.mttaMinutes)} icon={Clock} hint="average, last 30 days" />
        <StatTile label="Time to contain" value={formatDuration(d.metrics.mttcMinutes)} icon={ShieldCheck} hint="average, last 30 days" />
        <StatTile label="Endpoints protected" value={d.endpoints.avgScore == null ? "—" : `${d.endpoints.avgScore}`} icon={Laptop} hint={`${d.endpoints.total} endpoints · ${d.endpoints.isolated} isolated`} />
      </div>

      {pending.length > 0 && (
        <Card className="border-warning/50 bg-warning/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Workflow className="size-4" /> Waiting for your approval</CardTitle>
            <CardDescription>Your SOC has proposed containment on your systems.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="flex flex-col gap-2 text-sm">
              {pending.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-2">
                  <span>{a.actionType.toLowerCase().replaceAll("_", " ")} <code className="text-xs">{a.target}</code></span>
                  <Button size="sm" variant="outline" asChild><Link href={`/cases/${a.case.id}`}>Review</Link></Button>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Incidents, last 14 days</CardTitle>
          </CardHeader>
          <CardContent>
            <CaseVolumeChart days={d.trend} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Your service</CardTitle>
            <CardDescription>{plan ? plan.tagline ?? plan.name : "Your service plan hasn't been set up yet."}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            {plan && <p className="flex justify-between"><span className="text-muted-foreground">Coverage</span><span>{plan.coverage}</span></p>}
            {plan?.ackMinutes.CRITICAL != null && <p className="flex justify-between"><span className="text-muted-foreground">Critical acknowledged within</span><span>{formatMinutes(plan.ackMinutes.CRITICAL)}</span></p>}
            <p className="flex justify-between"><span className="text-muted-foreground">AI containment consent</span><span>{AUTONOMY_LABEL[tenant.aiAutonomyCap]}</span></p>
            <Button variant="outline" size="sm" asChild className="mt-2">
              <Link href={`/tenants/${tenant.id}`}>Service details &amp; AI consent</Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-2">
          <CardTitle className="text-base">Recent incidents</CardTitle>
          <Button variant="outline" size="sm" asChild><Link href="/cases">All incidents</Link></Button>
        </CardHeader>
        <CardContent>
          {d.recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">No incidents. Your SOC is monitoring around the clock.</p>
          ) : (
            <ul className="divide-y">
              {d.recent.map((c) => (
                <li key={c.id} className="flex items-center justify-between gap-3 py-2.5">
                  <div className="min-w-0">
                    <Link href={`/cases/${c.id}`} className="block truncate text-sm font-medium hover:underline">{c.title}</Link>
                    <p className="text-xs text-muted-foreground">{CASE_STATUS_LABEL[c.status]} · {formatRelative(c.createdAt, d.now)}</p>
                  </div>
                  <SeverityBadge severity={c.severity} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

async function CommercialOverview({ user }: { user: SessionUser }) {
  const d = await loadCommercialDashboard();
  const endpoints = d.tenants.reduce((s, t) => s + t.endpointsLicensed, 0);
  return (
    <div className="flex flex-col gap-6">
      <div>
        <p className="text-sm text-muted-foreground">{greeting(d.now)}, {user.name?.split(" ")[0] ?? ""}</p>
        <h2 className="text-xl font-semibold tracking-tight">Commercial overview</h2>
      </div>
      <Card className="surface-glow">
        <CardContent className="flex flex-wrap items-center justify-between gap-6 py-2">
          <div>
            <p className="text-sm text-muted-foreground">Won monthly recurring revenue</p>
            <p className="text-5xl font-semibold tracking-tight">{formatMoney(d.wonMonthly, "USD", 1, { decimals: 0 })}</p>
          </div>
          <Button asChild><Link href="/pricing">Build a quote</Link></Button>
        </CardContent>
      </Card>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Open pipeline / month" value={formatMoney(d.pipelineMonthly, "USD", 1, { decimals: 0 })} icon={TrendingUp} hint={`${d.counts.sent} quotes sent`} />
        <StatTile label="Win rate" value={d.winRate == null ? "—" : `${Math.round(d.winRate * 100)}%`} icon={CircleCheck} hint={`${d.counts.accepted} won · ${d.counts.lost} lost`} />
        <StatTile label="Clients" value={d.tenants.length} icon={Building2} hint={`${d.tenants.filter((t) => t.status === "ACTIVE").length} active`} />
        <StatTile label="Endpoints under contract" value={endpoints.toLocaleString()} icon={Laptop} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base"><FileText className="size-4" /> Recent quotes</CardTitle>
        </CardHeader>
        <CardContent>
          {d.quotes.length === 0 ? (
            <p className="text-sm text-muted-foreground">No quotes yet.</p>
          ) : (
            <ul className="divide-y">
              {d.quotes.map((q) => {
                const totals = q.totals as unknown as QuoteResult;
                return (
                  <li key={q.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <Link href={`/pricing/quotes/${q.id}`} className="block truncate text-sm font-medium hover:underline">{q.clientName}</Link>
                      <p className="font-mono text-[11px] text-muted-foreground">{q.reference} · {formatRelative(q.updatedAt, d.now)}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm tabular">{formatMoney(totals.monthlyNet, q.currency, totals.fxRate, { decimals: 0 })}/mo</span>
                      <Badge variant={q.status === "ACCEPTED" ? "success" : q.status === "SENT" ? "info" : q.status === "LOST" ? "soft" : "outline"}>{q.status.toLowerCase()}</Badge>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
