import Link from "next/link";
import { forbidden, notFound } from "next/navigation";
import { ArrowLeft, Bot, Clock, Laptop, Plug, ShieldAlert, Timer, TrendingUp, Users } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can, roleLabel } from "@/lib/rbac";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { PLAN_FEATURES, PLAN_FEATURE_LABEL, parsePlan } from "@/lib/plans";
import { listPlans } from "@/lib/service-plans";
import { AUTONOMY_LABEL } from "@/lib/ai/catalog";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { serviceMetrics, formatDuration } from "@/lib/metrics";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { TestBadge } from "@/components/shared/test-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge, StatusBadge } from "@/components/shared/case-badges";
import { AiConsentSelect, TenantFormButton } from "@/components/tenants/tenant-form";

async function loadTenant(id: string) {
  const now = new Date();
  const since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const tenant = await db.tenant.findUnique({
    where: { id },
    include: {
      users: { orderBy: { name: "asc" }, select: { id: true, name: true, email: true, role: true, active: true, lastLoginAt: true } },
      integrations: { orderBy: { createdAt: "asc" }, select: { id: true, name: true, status: true, enabled: true, lastEventAt: true } },
      _count: { select: { endpoints: true } },
      plan: true,
    },
  });
  if (!tenant) return null;
  const [metrics, openCases, isolated, plans] = await Promise.all([
    serviceMetrics({ tenantId: id }, since, now),
    db.case.findMany({ where: { tenantId: id, status: { notIn: CLOSED_STATUSES } }, orderBy: [{ severity: "desc" }, { createdAt: "desc" }], take: 10 }),
    db.endpoint.count({ where: { tenantId: id, isolated: true } }),
    listPlans(),
  ]);
  return { now, tenant, metrics, openCases, isolated, plans };
}

export default async function TenantPage({ params }: PageProps<"/tenants/[id]">) {
  const { id } = await params;
  const user = await pageGuard();
  const own = user.isClient && user.tenantId === id;
  if (!own && !can(user, "tenants.view")) forbidden();
  const data = await loadTenant(id);
  if (!data) notFound();
  const { now, tenant, metrics, openCases, isolated, plans } = data;
  const plan = tenant.plan ? parsePlan(tenant.plan) : null;
  const canEditConsent = can(user, "tenants.manage") || (own && user.role === "CLIENT_ADMIN");

  return (
    <div className="flex flex-col gap-6">
      {!user.isClient && (
        <div>
          <Button variant="ghost" size="sm" asChild className="-ml-2">
            <Link href="/tenants"><ArrowLeft /> Clients</Link>
          </Button>
        </div>
      )}

      <Card className="surface-glow">
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Badge variant={tenant.status === "ACTIVE" ? "success" : tenant.status === "SUSPENDED" ? "destructive" : "info"}>{tenant.status.toLowerCase()}</Badge>
              <Badge variant="outline">{plan?.name ?? "No plan"}</Badge>
              {tenant.isTest && <TestBadge />}
              {tenant.industry && <span className="text-xs text-muted-foreground">{tenant.industry}</span>}
            </div>
            <CardTitle className="mt-2 text-xl">{tenant.name}</CardTitle>
            <CardDescription>
              {plan?.tagline}
              {tenant.contactName && `${plan?.tagline ? " · " : ""}Contact: ${tenant.contactName}${tenant.contactEmail ? ` <${tenant.contactEmail}>` : ""}`}
            </CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2">
          {can(user, "pricing.view") && (
            <Button asChild size="sm" variant="outline">
              <Link href={`/pricing?tenant=${tenant.id}&tab=upgrades`}><TrendingUp /> Review upgrades &amp; price</Link>
            </Button>
          )}
          {can(user, "tenants.manage") && (
            <TenantFormButton
              tenantId={tenant.id}
              plans={[...plans, ...(plan && !plans.some((p) => p.id === plan.id) ? [plan] : [])].map((p) => ({ id: p.id, name: p.name, tagline: p.tagline }))}
              initial={{
                name: tenant.name,
                industry: tenant.industry ?? "",
                planId: tenant.planId,
                status: tenant.status,
                contactName: tenant.contactName ?? "",
                contactEmail: tenant.contactEmail ?? "",
                endpointsLicensed: tenant.endpointsLicensed,
                usersLicensed: tenant.usersLicensed,
                notes: tenant.notes ?? "",
                isTest: tenant.isTest,
              }}
            />
          )}
          </div>
        </CardHeader>
        {tenant.notes && !user.isClient && <CardContent className="text-sm whitespace-pre-wrap text-muted-foreground">{tenant.notes}</CardContent>}
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="Open cases" value={openCases.length} icon={ShieldAlert} tone={openCases.some((c) => c.severity === "CRITICAL") ? "critical" : "default"} />
        <StatTile label="SLA met (30d)" value={metrics.slaCompliance == null ? "—" : `${Math.round(metrics.slaCompliance * 100)}%`} icon={Timer} />
        <StatTile label="Mean time to acknowledge" value={formatDuration(metrics.mttaMinutes)} icon={Clock} />
        <StatTile label="Mean time to contain" value={formatDuration(metrics.mttcMinutes)} icon={ShieldAlert} />
        <StatTile label="Endpoints (isolated)" value={`${tenant._count.endpoints}${isolated ? ` (${isolated})` : ""}`} icon={Laptop} tone={isolated ? "warning" : "default"} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Open cases</CardTitle>
          </CardHeader>
          <CardContent>
            {openCases.length === 0 ? (
              <p className="text-sm text-muted-foreground">Nothing open. 🎉</p>
            ) : (
              <ul className="divide-y">
                {openCases.map((c) => (
                  <li key={c.id} className="flex items-center justify-between gap-3 py-2">
                    <div className="min-w-0">
                      <Link href={`/cases/${c.id}`} className="block truncate text-sm font-medium hover:underline">{c.title}</Link>
                      <p className="text-xs text-muted-foreground">{formatRelative(c.createdAt, now)}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <StatusBadge status={c.status} />
                      <SeverityBadge severity={c.severity} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Bot className="size-4" /> AI consent</CardTitle>
            <CardDescription>The most an AI agent may do on this client&apos;s systems, whatever the SOC&apos;s own settings say.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <AiConsentSelect tenantId={tenant.id} value={tenant.aiAutonomyCap} canEdit={canEditConsent} />
            <p className="text-xs text-muted-foreground">
              Currently: <span className="font-medium text-foreground">{AUTONOMY_LABEL[tenant.aiAutonomyCap]}</span>. Business-critical endpoints always need a human, and user
              account actions always need approval.
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Service level</CardTitle>
            <CardDescription>{plan ? `${plan.name} · ${plan.coverage} coverage` : "No service plan — cases for this client have no SLA."}</CardDescription>
          </CardHeader>
          <CardContent>
            {plan && (
            <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">Acknowledge</TableHead>
                  <TableHead className="text-right">Contain</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SEVERITY_ORDER.filter((s) => plan.ackMinutes[s] != null || plan.containMinutes[s] != null).map((s) => (
                  <TableRow key={s}>
                    <TableCell>{SEVERITY_LABEL[s]}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatDuration(plan.ackMinutes[s])}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatDuration(plan.containMinutes[s])}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <ul className="mt-3 space-y-1 text-xs">
              {PLAN_FEATURES.map((f) => (
                <li key={f} className="flex justify-between gap-2">
                  <span className="text-muted-foreground">{PLAN_FEATURE_LABEL[f]}</span>
                  <span className="text-right">{plan.features[f] === true ? "Included" : typeof plan.features[f] === "string" ? String(plan.features[f]) : "—"}</span>
                </li>
              ))}
            </ul>
            </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Plug className="size-4" /> Tools</CardTitle>
          </CardHeader>
          <CardContent>
            {tenant.integrations.length === 0 ? (
              <p className="text-sm text-muted-foreground">No tools onboarded yet.</p>
            ) : (
              <ul className="flex flex-col gap-2 text-sm">
                {tenant.integrations.map((i) => (
                  <li key={i.id} className="flex items-center justify-between gap-2">
                    <span className="truncate">{i.name}</span>
                    <Badge variant={!i.enabled ? "outline" : i.status === "CONNECTED" ? "success" : i.status === "DEGRADED" ? "warning" : "soft"}>
                      {i.enabled ? i.status.toLowerCase() : "disabled"}
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
            {can(user, "integrations.view") && (
              <Button asChild variant="link" size="sm" className="mt-2 px-0">
                <Link href="/integrations">Manage tools →</Link>
              </Button>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Users className="size-4" /> Client users</CardTitle>
          </CardHeader>
          <CardContent>
            {tenant.users.length === 0 ? (
              <p className="text-sm text-muted-foreground">No portal users yet{can(user, "users.manage") ? " — invite them under Team & Roles." : "."}</p>
            ) : (
              <ul className="flex flex-col gap-2 text-sm">
                {tenant.users.map((u) => (
                  <li key={u.id} className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <p className="truncate">{u.name ?? u.email}</p>
                      <p className="text-[11px] text-muted-foreground">{roleLabel(u.role)}{u.lastLoginAt ? ` · last login ${formatRelative(u.lastLoginAt, now)}` : " · never signed in"}</p>
                    </div>
                    {!u.active && <Badge variant="outline">inactive</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
