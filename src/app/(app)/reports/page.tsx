import Link from "next/link";
import { BadgeCheck, Bot, CalendarRange, CheckCircle2, Download, Inbox, Timer, TimerReset, Zap } from "lucide-react";
import type { CaseSeverity, CaseSource, SecurityDomain } from "@prisma/client";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { caseScope, selectedTenantId } from "@/lib/access";
import { DOMAIN_LABEL } from "@/lib/rbac";
import { CASE_SOURCE_LABEL } from "@/lib/cases/labels";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/lib/severity";
import { ACTION_LABEL } from "@/lib/response/executor";
import { formatDuration, loadServiceReport, parseRange, type ReportRange } from "@/lib/reports";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { BarList } from "@/components/dashboard/bar-list";
import { TrendChart } from "@/components/reports/trend-chart";
import { TestBadge } from "@/components/shared/test-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const PRESETS = [
  { key: "7d", label: "7 days" },
  { key: "30d", label: "30 days" },
  { key: "90d", label: "90 days" },
  { key: "365d", label: "12 months" },
];

function recentMonths(now: Date) {
  return Array.from({ length: 12 }, (_, i) => {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    return { key: d.toISOString().slice(0, 7), label: d.toLocaleDateString("en-US", { month: "short", year: "numeric", timeZone: "UTC" }) };
  });
}

// "12% more than the previous period", in words: whether more is better
// depends on the metric, so no colored arrows.
function versus(current: number | null, previous: number | null, unit: "count" | "time" | "pct") {
  if (current == null || previous == null) return "No earlier period to compare";
  if (unit === "pct") {
    const d = Math.round((current - previous) * 100);
    return d === 0 ? "Same as the previous period" : `${Math.abs(d)} pts ${d > 0 ? "higher" : "lower"} than the previous period`;
  }
  if (previous === 0) return current === 0 ? "Same as the previous period" : "None in the previous period";
  const d = Math.round(((current - previous) / previous) * 100);
  if (d === 0) return "Same as the previous period";
  return unit === "time" ? `${Math.abs(d)}% ${d > 0 ? "slower" : "faster"} than the previous period` : `${Math.abs(d)}% ${d > 0 ? "more" : "fewer"} than the previous period`;
}

function pct(n: number | null) {
  return n == null ? "—" : `${Math.round(n * 100)}%`;
}

async function loadReport(user: Awaited<ReturnType<typeof pageGuard>>, sp: { range?: string; month?: string }) {
  const now = new Date();
  const range = parseRange(sp, now);
  const [scope, selected] = await Promise.all([caseScope(user), selectedTenantId(user)]);
  const [report, tenant] = await Promise.all([
    loadServiceReport(scope, range, now),
    selected ? db.tenant.findUnique({ where: { id: selected }, select: { name: true, isTest: true } }) : Promise.resolve(null),
  ]);
  return { now, range, report, tenant };
}

export default async function ReportsPage({ searchParams }: PageProps<"/reports">) {
  const user = await pageGuard("reports.view");
  const sp = await searchParams;
  const { now, range, report, tenant } = await loadReport(user, { range: typeof sp.range === "string" ? sp.range : undefined, month: typeof sp.month === "string" ? sp.month : undefined });
  const s = report.summary;
  const p = report.previousSummary;
  const staff = !user.isClient;
  const query = (r: Pick<ReportRange, "key">) => (/^\d{4}-\d{2}$/.test(r.key) ? `month=${r.key}` : `range=${r.key}`);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <CalendarRange className="size-4" /> {range.label} · {range.from.toISOString().slice(0, 10)} to {new Date(range.to.getTime() - 1).toISOString().slice(0, 10)}
          </p>
          <h2 className="flex items-center gap-2 text-xl font-semibold tracking-tight">
            {user.isClient ? `Service report — ${user.tenantName ?? "your organization"}` : tenant ? `Service report — ${tenant.name}` : "Service report — all clients"}
            {tenant?.isTest && <TestBadge />}
          </h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <nav aria-label="Period" className="flex rounded-md border p-0.5">
            {PRESETS.map((r) => (
              <Link key={r.key} href={`/reports?range=${r.key}`} aria-current={range.key === r.key ? "page" : undefined} className={cn("rounded px-2.5 py-1 text-xs font-medium text-muted-foreground hover:text-foreground", range.key === r.key && "bg-muted text-foreground")}>
                {r.label}
              </Link>
            ))}
          </nav>
          <details className="relative">
            <summary className="flex h-8 cursor-pointer list-none items-center rounded-md border px-2.5 text-xs font-medium text-muted-foreground hover:text-foreground">
              {/^\d{4}-\d{2}$/.test(range.key) ? range.label : "Month…"}
            </summary>
            <div className="absolute right-0 z-20 mt-1 grid w-40 gap-0.5 rounded-md border bg-popover p-1 shadow-md">
              {recentMonths(now).map((m) => (
                <Link key={m.key} href={`/reports?month=${m.key}`} className={cn("rounded px-2 py-1 text-xs hover:bg-accent", range.key === m.key && "bg-muted font-medium")}>{m.label}</Link>
              ))}
            </div>
          </details>
          <Button size="sm" variant="outline" asChild>
            <a href={`/reports/pdf?${query(range)}`}><Download /> PDF</a>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatTile label="Cases opened" value={s.opened} icon={Inbox} hint={versus(s.opened, p.opened, "count")} />
        <StatTile label="Cases closed" value={s.closed} icon={CheckCircle2} hint={s.closed ? `${s.falsePositives} false positive${s.falsePositives === 1 ? "" : "s"}` : undefined} />
        <StatTile label="Open now" value={report.openNow} icon={Zap} />
        <StatTile label="Median time to acknowledge" value={formatDuration(s.medianAcknowledgeMs)} icon={Timer} hint={versus(s.medianAcknowledgeMs, p.medianAcknowledgeMs, "time")} />
        <StatTile label="Median time to resolve" value={formatDuration(s.medianResolveMs)} icon={TimerReset} hint={versus(s.medianResolveMs, p.medianResolveMs, "time")} />
        <StatTile
          label="Acknowledged within SLA"
          value={pct(s.sla.compliance)}
          icon={BadgeCheck}
          tone={s.sla.compliance != null && s.sla.compliance < 0.9 ? "warning" : "default"}
          hint={s.sla.met + s.sla.breached ? `${s.sla.met} met · ${s.sla.breached} breached${s.sla.pending ? ` · ${s.sla.pending} still open` : ""}` : "No cases with an SLA"}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cases opened and closed</CardTitle>
          <CardDescription>
            {range.to.getTime() - range.from.getTime() > 62 * 86_400_000 ? "Per week (Monday, UTC)." : "Per day (UTC)."} Median time to contain: {formatDuration(s.medianContainMs)}.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {s.opened + s.closed === 0 ? <p className="text-sm text-muted-foreground">No cases were opened or closed in this period.</p> : <TrendChart points={report.trend} />}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle className="text-base">By severity</CardTitle></CardHeader>
          <CardContent>
            <BarList items={SEVERITY_ORDER.filter((sev) => s.bySeverity[sev as CaseSeverity]).map((sev) => ({ label: SEVERITY_LABEL[sev as CaseSeverity], value: s.bySeverity[sev as CaseSeverity] ?? 0, href: `/cases?status=all&severity=${sev}` }))} emptyText="No cases opened." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">By source</CardTitle></CardHeader>
          <CardContent>
            <BarList items={Object.entries(s.bySource).map(([src, n]) => ({ label: CASE_SOURCE_LABEL[src as CaseSource], value: n ?? 0 })).sort((a, b) => b.value - a.value)} emptyText="No cases opened." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-base">By security domain</CardTitle></CardHeader>
          <CardContent>
            <BarList items={Object.entries(s.byDomain).map(([d, n]) => ({ label: d === "UNASSIGNED" ? "Unassigned" : DOMAIN_LABEL[d as SecurityDomain], value: n })).sort((a, b) => b.value - a.value)} emptyText="No cases opened." />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top ATT&amp;CK techniques</CardTitle>
            <CardDescription>Cases opened in the period, per technique.</CardDescription>
          </CardHeader>
          <CardContent>
            <BarList items={report.techniques.map((t) => ({ label: `${t.id} ${t.name}`, value: t.count, href: `/cases?status=all&technique=${t.id}` }))} emptyText="No cases mapped to ATT&CK in this period." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Malicious indicators</CardTitle>
            <CardDescription>Known-bad indicators (reputation ≥ 0.70) in the most cases.</CardDescription>
          </CardHeader>
          <CardContent>
            {report.indicators.length === 0 ? (
              <p className="text-sm text-muted-foreground">No known-malicious indicators in this period&apos;s cases.</p>
            ) : (
              <Table>
                <TableHeader><TableRow><TableHead>Indicator</TableHead><TableHead className="text-right">Reputation</TableHead><TableHead className="text-right">Cases</TableHead></TableRow></TableHeader>
                <TableBody>
                  {report.indicators.map((i) => (
                    <TableRow key={`${i.type}:${i.value}`}>
                      <TableCell className="max-w-64 truncate font-mono text-xs" title={i.value}><span className="mr-1.5 text-muted-foreground">{i.type.toLowerCase().replace("_", " ")}</span>{i.value}</TableCell>
                      <TableCell className="text-right tabular">{i.score.toFixed(2)}</TableCell>
                      <TableCell className="text-right tabular">{i.cases}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Bot className="size-4" /> AI first responder</CardTitle>
            <CardDescription>Agent runs on this period&apos;s cases, and how analysts rated them.</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
            <Metric label="Runs" value={report.ai.runs} hint={`${report.ai.automatic} automatic`} />
            <Metric label="On local models" value={report.ai.local} />
            <Metric label="Median run time" value={formatDuration(report.ai.medianDurationMs)} />
            <Metric label="Succeeded" value={report.ai.byStatus.succeeded ?? 0} hint={`${report.ai.byStatus.fallback ?? 0} fell back · ${report.ai.byStatus.failed ?? 0} failed`} />
            <Metric label="Analyst agreement" value={report.ai.rated ? pct(report.ai.agreed / report.ai.rated) : "—"} hint={`${report.ai.rated} rated`} />
            <Metric label="Containment steps" value={report.actions.total} hint={`${report.actions.fromAi} proposed by AI`} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Response actions</CardTitle>
            <CardDescription>Containment requested in the period, by outcome.</CardDescription>
          </CardHeader>
          <CardContent>
            <BarList
              items={Object.entries(report.actions.byStatus).map(([status, n]) => ({ label: status.toLowerCase().replaceAll("_", " "), value: n })).sort((a, b) => b.value - a.value)}
              emptyText="No containment was requested."
            />
            {report.actions.total > 0 && (
              <p className="mt-3 text-xs text-muted-foreground">
                Most requested: {Object.entries(report.actions.byType).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([type, n]) => `${ACTION_LABEL[type as keyof typeof ACTION_LABEL] ?? type} (${n})`).join(", ")}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {staff && !tenant && report.tenants.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">By client</CardTitle>
            <CardDescription>Cases opened in the period. Pick a client in the top bar for its own report.</CardDescription>
          </CardHeader>
          <CardContent>
            <BarList items={report.tenants.map((t) => ({ label: `${t.name}${t.isTest && !/^test\b/i.test(t.name) ? " (test)" : ""}`, value: t.count, href: t.id === "internal" ? undefined : `/tenants/${t.id}` }))} />
          </CardContent>
        </Card>
      )}

      {staff && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Analyst workload</CardTitle>
            <CardDescription>Assigned cases still open, and cases closed in the period by their assignee.</CardDescription>
          </CardHeader>
          <CardContent>
            {report.analysts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No assigned cases in this period.</p>
            ) : (
              <Table>
                <TableHeader><TableRow><TableHead>Analyst</TableHead><TableHead className="text-right">Open assigned</TableHead><TableHead className="text-right">Closed</TableHead><TableHead className="text-right">Median time to resolve</TableHead></TableRow></TableHeader>
                <TableBody>
                  {report.analysts.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell>{a.name}</TableCell>
                      <TableCell className="text-right tabular">{a.openAssigned}</TableCell>
                      <TableCell className="text-right tabular">{a.closed}</TableCell>
                      <TableCell className="text-right tabular">{formatDuration(a.medianResolveMs)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold tabular">{value}</p>
      {hint && <p className="text-[11px] text-muted-foreground">{hint}</p>}
    </div>
  );
}
