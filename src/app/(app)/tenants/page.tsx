import Link from "next/link";
import { Building2, Laptop, ShieldAlert, Users } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { listPlans } from "@/lib/service-plans";
import { AUTONOMY_LABEL } from "@/lib/ai/catalog";
import { computeMetrics, formatDuration } from "@/lib/metrics";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { TestBadge } from "@/components/shared/test-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";
import { TenantFormButton } from "@/components/tenants/tenant-form";

const STATUS_VARIANT = { ACTIVE: "success", ONBOARDING: "info", SUSPENDED: "destructive" } as const;

async function loadTenants() {
  const now = new Date();
  const since = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const tenants = await db.tenant.findMany({
    orderBy: { name: "asc" },
    include: { _count: { select: { users: true, endpoints: true, integrations: true } }, plan: { select: { name: true, coverage: true } } },
  });
  const [open, critical, recent] = await Promise.all([
    db.case.groupBy({ by: ["tenantId"], where: { status: { notIn: CLOSED_STATUSES } }, _count: { _all: true } }),
    db.case.groupBy({ by: ["tenantId"], where: { status: { notIn: CLOSED_STATUSES }, severity: "CRITICAL" }, _count: { _all: true } }),
    db.case.findMany({ where: { createdAt: { gte: since }, tenantId: { not: null } }, select: { tenantId: true, createdAt: true, acknowledgedAt: true, containedAt: true, resolvedAt: true, slaDueAt: true } }),
  ]);
  const count = (rows: Array<{ tenantId: string | null; _count: { _all: number } }>, id: string) => rows.find((r) => r.tenantId === id)?._count._all ?? 0;
  return tenants.map((t) => ({
    ...t,
    open: count(open, t.id),
    critical: count(critical, t.id),
    metrics: computeMetrics(recent.filter((r) => r.tenantId === t.id), now),
  }));
}

export default async function TenantsPage() {
  const user = await pageGuard("tenants.view");
  const [tenants, plans] = await Promise.all([loadTenants(), listPlans()]);
  const active = tenants.filter((t) => t.status === "ACTIVE").length;
  const endpoints = tenants.reduce((s, t) => s + t.endpointsLicensed, 0);
  const seats = tenants.reduce((s, t) => s + t.usersLicensed, 0);
  const critical = tenants.reduce((s, t) => s + t.critical, 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Active clients" value={`${active} / ${tenants.length}`} icon={Building2} />
        <StatTile label="Endpoints under contract" value={endpoints.toLocaleString()} icon={Laptop} />
        <StatTile label="Users under contract" value={seats.toLocaleString()} icon={Users} />
        <StatTile label="Open critical cases" value={critical} icon={ShieldAlert} tone={critical > 0 ? "critical" : "default"} />
      </div>
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">Clients</CardTitle>
            <CardDescription>Each client&apos;s plan, live risk, service performance over the last 30 days, and how much autonomy they&apos;ve given AI agents.</CardDescription>
          </div>
          {can(user, "tenants.manage") && <TenantFormButton plans={plans.map((p) => ({ id: p.id, name: p.name, tagline: p.tagline }))} />}
        </CardHeader>
        <CardContent>
          {tenants.length === 0 ? (
            <EmptyState icon={Building2} title="No clients yet" description="Create your first client tenant to start onboarding their tools." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Client</TableHead>
                    <TableHead>Plan</TableHead>
                    <TableHead className="text-right">Open (critical)</TableHead>
                    <TableHead className="text-right">SLA (30d)</TableHead>
                    <TableHead className="text-right">MTTA</TableHead>
                    <TableHead className="text-right">Endpoints</TableHead>
                    <TableHead className="text-right">Tools</TableHead>
                    <TableHead>AI consent</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tenants.map((t) => {
                    const sla = t.metrics.slaCompliance;
                    return (
                      <TableRow key={t.id}>
                        <TableCell>
                          <Link href={`/tenants/${t.id}`} className="font-medium hover:underline">{t.name}</Link>
                          <div className="mt-0.5 flex items-center gap-1.5">
                            <Badge variant={STATUS_VARIANT[t.status]}>{t.status.toLowerCase()}</Badge>
                            {t.isTest && <TestBadge />}
                            {t.industry && <span className="text-[11px] text-muted-foreground">{t.industry}</span>}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">{t.plan?.name ?? <span className="text-muted-foreground">No plan</span>}{t.plan && <p className="text-[11px] text-muted-foreground">{t.plan.coverage}</p>}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {t.open}
                          {t.critical > 0 && <span className="ml-1 text-destructive">({t.critical})</span>}
                        </TableCell>
                        <TableCell className={`text-right tabular-nums ${sla == null ? "text-muted-foreground" : sla >= 0.95 ? "text-success-ink" : sla >= 0.8 ? "text-warning-ink" : "text-destructive"}`}>
                          {sla == null ? "—" : `${Math.round(sla * 100)}%`}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{formatDuration(t.metrics.mttaMinutes)}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {t._count.endpoints}
                          <span className="text-muted-foreground"> / {t.endpointsLicensed}</span>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{t._count.integrations}</TableCell>
                        <TableCell className="text-xs">{AUTONOMY_LABEL[t.aiAutonomyCap]}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
