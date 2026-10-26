import Link from "next/link";
import { Laptop, Lock, ShieldAlert, ShieldCheck, TimerOff } from "lucide-react";
import type { Prisma } from "@prisma/client";

import { db } from "@/lib/db";
import { dbFor, type ScopedDb } from "@/lib/tenant-db";
import { pageGuard } from "@/lib/session";
import { can } from "@/lib/rbac";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { tenantOptions } from "@/lib/tenants";
import { CLOSED_STATUSES } from "@/lib/cases/labels";
import { CONTROLS, coverageScore, missingEssentials, parseProtections } from "@/lib/endpoints/controls";
import { ASSET_CLASSES, type AssetClass } from "@/lib/assets/surface";
import { DEVICE_CLASSES, assetTypeLabel, endpointClass, isAssetClass } from "@/lib/assets/inventory";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { TestBadge } from "@/components/shared/test-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState } from "@/components/shared/empty-state";
import { CriticalitySelect, InventoryImport, IsolationButton } from "@/components/endpoints/endpoint-controls";

const STALE_DAYS = 7;
const CELL = { active: "bg-success", degraded: "bg-warning", missing: "bg-destructive/70" } as const;

function one(v: string | string[] | undefined) {
  return Array.isArray(v) ? v[0] : v;
}

async function loadEndpoints(client: ScopedDb, scope: { tenantId?: string | null }, q: string | undefined, filter: string | undefined, cls: AssetClass | undefined) {
  const now = new Date();
  const staleBefore = new Date(now.getTime() - STALE_DAYS * 24 * 60 * 60 * 1000);
  const where: Prisma.EndpointWhereInput = { ...scope };
  if (q) where.OR = [{ hostname: { contains: q, mode: "insensitive" } }, { owner: { contains: q, mode: "insensitive" } }, { ipAddress: { contains: q } }];
  if (filter === "isolated") where.isolated = true;
  if (filter === "stale") where.lastSeenAt = { lt: staleBefore };
  if (filter === "critical") where.criticality = "critical";

  const everything = await client.endpoint.findMany({ where: scope, select: { id: true, protections: true, isolated: true, lastSeenAt: true, os: true, assetClass: true, assetType: true } });
  const classOf = new Map(everything.map((e) => [e.id, endpointClass(e)]));
  // Device controls apply to computers, servers and phones only.
  const all = everything.filter((e) => DEVICE_CLASSES.includes(classOf.get(e.id)!));
  if (cls) where.id = { in: everything.filter((e) => classOf.get(e.id) === cls).map((e) => e.id).slice(0, 5000) };
  const endpoints = await client.endpoint.findMany({ where, orderBy: [{ isolated: "desc" }, { lastSeenAt: { sort: "desc", nulls: "last" } }], take: 200, include: { tenant: { select: { name: true, isTest: true } } } });
  const byClass = ASSET_CLASSES.map((c) => {
    const rows = everything.filter((e) => classOf.get(e.id) === c.key);
    const types = new Map<string, number>();
    for (const r of rows) if (r.assetType) types.set(r.assetType, (types.get(r.assetType) ?? 0) + 1);
    return { info: c, count: rows.length, types: [...types].sort((a, b) => b[1] - a[1]).slice(0, 3) };
  });

  // Open cases per host, from the telemetry linked to them.
  const hostRows = endpoints.length
    ? await db.securityEvent.findMany({
        where: { hostName: { in: endpoints.map((e) => e.hostname) }, case: { status: { notIn: CLOSED_STATUSES } } },
        distinct: ["hostName", "caseId"],
        select: { hostName: true, caseId: true },
      })
    : [];
  const openCases = new Map<string, number>();
  for (const r of hostRows) if (r.hostName) openCases.set(r.hostName.toLowerCase(), (openCases.get(r.hostName.toLowerCase()) ?? 0) + 1);

  const parsed = all.map((e) => parseProtections(e.protections));
  const controlCoverage = CONTROLS.map((c) => ({
    ...c,
    active: parsed.filter((p) => p[c.key]?.status === "active").length,
    degraded: parsed.filter((p) => p[c.key]?.status === "degraded").length,
  }));
  return {
    now,
    staleBefore,
    endpoints,
    openCases,
    total: all.length,
    assets: everything.length,
    byClass,
    isolated: all.filter((e) => e.isolated).length,
    stale: all.filter((e) => !e.lastSeenAt || e.lastSeenAt < staleBefore).length,
    gaps: parsed.filter((p) => missingEssentials(p).length > 0).length,
    avgScore: parsed.length ? Math.round(parsed.reduce((s, p) => s + coverageScore(p), 0) / parsed.length) : 0,
    controlCoverage,
  };
}

export default async function EndpointsPage({ searchParams }: PageProps<"/endpoints">) {
  const user = await pageGuard("endpoints.view");
  const sp = await searchParams;
  const q = one(sp.q)?.trim() || undefined;
  const filter = one(sp.filter);
  const cls = isAssetClass(one(sp.class)) ? (one(sp.class) as AssetClass) : undefined;
  const scope = await tenantScope(user);
  const [data, tenants, defaultTenantId] = await Promise.all([loadEndpoints(dbFor(user), scope, q, filter, cls), tenantOptions(), selectedTenantId(user)]);
  const href = (c: AssetClass | undefined) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (filter) params.set("filter", filter);
    if (c) params.set("class", c);
    return `/endpoints${params.size ? `?${params}` : ""}`;
  };
  const canContain = can(user, "endpoints.contain");
  const canEdit = canContain || can(user, "integrations.manage");

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="Assets (devices)" value={data.assets === data.total ? data.total : `${data.assets} (${data.total})`} icon={Laptop} />
        <StatTile label="Avg. protection score" value={`${data.avgScore}`} icon={ShieldCheck} tone={data.avgScore < 60 && data.total > 0 ? "warning" : "default"} />
        <StatTile label="Devices missing essential controls" value={data.gaps} icon={ShieldAlert} tone={data.gaps > 0 ? "critical" : "default"} />
        <StatTile label="Isolated now" value={data.isolated} icon={Lock} tone={data.isolated > 0 ? "warning" : "default"} />
        <StatTile label={`Not seen in ${STALE_DAYS}d`} value={data.stale} icon={TimerOff} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Attack surface inventory</CardTitle>
          <CardDescription>Every asset by group: devices placed by their OS, and anything an import or tool files as network, cloud, identity, IoT/OT or application assets.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
          {data.byClass.map((c) => (
            <Link
              key={c.info.key}
              href={href(cls === c.info.key ? undefined : c.info.key)}
              aria-current={cls === c.info.key ? "true" : undefined}
              className={cn("rounded-lg border p-3 transition-colors hover:bg-accent", cls === c.info.key && "border-primary bg-primary/5 ring-1 ring-primary", c.count === 0 && "opacity-60")}
            >
              <p className="text-2xl font-semibold tabular">{c.count}</p>
              <p className="text-xs font-medium">{c.info.label}</p>
              {c.types.length > 0 && <p className="mt-0.5 truncate text-[11px] text-muted-foreground">{c.types.map(([t, n]) => `${n} ${assetTypeLabel(c.info.key, t) ?? t}`).join(" · ")}</p>}
            </Link>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Protection coverage by control</CardTitle>
          <CardDescription>Share of computers, servers and phones where each protection layer is active, from onboarded tools and imported inventory. Essential controls are marked.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-x-8 gap-y-2.5 md:grid-cols-2">
          {data.controlCoverage.map((c) => {
            const pct = data.total ? Math.round((c.active / data.total) * 100) : 0;
            const degradedPct = data.total ? Math.round((c.degraded / data.total) * 100) : 0;
            return (
              <div key={c.key} className="grid grid-cols-[9.5rem_1fr_3rem] items-center gap-3 text-sm">
                <span className="truncate" title={c.description}>
                  {c.label}
                  {c.essential && <span className="ml-1 text-[10px] font-semibold uppercase text-muted-foreground">ess.</span>}
                </span>
                <div className="flex h-2 overflow-hidden rounded-full bg-muted" role="img" aria-label={`${c.label}: ${pct}% active, ${degradedPct}% degraded`}>
                  <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
                  <div className="h-full bg-primary/35" style={{ width: `${degradedPct}%` }} />
                </div>
                <span className="text-right tabular text-muted-foreground">{pct}%</span>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">Inventory</CardTitle>
            <CardDescription>Hosts appear automatically from telemetry and onboarded tools. Business-critical hosts are never isolated by AI without approval.</CardDescription>
          </div>
          {can(user, "integrations.manage") && <InventoryImport tenants={tenants} defaultTenantId={user.isClient ? user.tenantId : defaultTenantId} isClient={user.isClient} />}
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <form className="flex flex-wrap gap-2" action="/endpoints">
            <Input name="q" defaultValue={q} placeholder="Hostname, owner or IP…" className="w-64" />
            <NativeSelect name="filter" defaultValue={filter ?? ""} aria-label="Filter">
              <option value="">All endpoints</option>
              <option value="isolated">Isolated</option>
              <option value="critical">Business-critical</option>
              <option value="stale">Not seen in {STALE_DAYS} days</option>
            </NativeSelect>
            {cls && <input type="hidden" name="class" value={cls} />}
            <Button type="submit" variant="secondary">Filter</Button>
            {(q || filter || cls) && (
              <Button variant="ghost" asChild>
                <Link href="/endpoints">Reset</Link>
              </Button>
            )}
          </form>

          {data.endpoints.length === 0 ? (
            <EmptyState icon={Laptop} title={cls ? "Nothing in this group yet" : "No endpoints yet"} description="Onboard an EDR under Tools & Integrations or import an inventory CSV; the class and type columns file network, cloud, IoT/OT and application assets." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    {!user.isClient && <TableHead>Client</TableHead>}
                    <TableHead>Controls</TableHead>
                    <TableHead className="text-right">Score</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead className="text-right">Open cases</TableHead>
                    <TableHead>Last seen</TableHead>
                    {canContain && <TableHead className="text-right">Containment</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.endpoints.map((e) => {
                    const group = endpointClass(e);
                    const device = DEVICE_CLASSES.includes(group);
                    const p = parseProtections(e.protections);
                    const score = coverageScore(p);
                    const missing = device ? missingEssentials(p) : [];
                    const cases = data.openCases.get(e.hostname.toLowerCase()) ?? 0;
                    const stale = !e.lastSeenAt || e.lastSeenAt < data.staleBefore;
                    return (
                      <TableRow key={e.id} className={cn(e.isolated && "bg-warning/5")}>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-sm font-medium">{e.hostname}</span>
                            {e.isolated && <Badge variant="warning"><Lock /> isolated</Badge>}
                          </div>
                          <p className="text-[11px] text-muted-foreground">{[assetTypeLabel(group, e.assetType) ?? ASSET_CLASSES.find((c) => c.key === group)?.label, e.os, e.ipAddress, e.owner].filter(Boolean).join(" · ")}</p>
                        </TableCell>
                        {!user.isClient && <TableCell className="text-xs">{e.tenant?.name ?? <span className="text-muted-foreground">Internal</span>}{e.tenant?.isTest && <TestBadge className="ml-1.5" />}</TableCell>}
                        <TableCell>
                          {!device ? <span className="text-xs text-muted-foreground">Monitored through its tools</span> : <>
                          <div className="flex gap-0.5">
                            {CONTROLS.map((c) => {
                              const st = p[c.key]?.status ?? "missing";
                              return (
                                <Tooltip key={c.key}>
                                  <TooltipTrigger asChild>
                                    <span className={cn("block h-4 w-2.5 rounded-[2px]", p[c.key] ? CELL[st] : "bg-muted", c.essential && !p[c.key] && "ring-1 ring-destructive/50")} />
                                  </TooltipTrigger>
                                  <TooltipContent>
                                    {c.label}: {p[c.key] ? `${st}${p[c.key]?.product ? ` (${p[c.key]?.product})` : ""}` : "not reported"}
                                  </TooltipContent>
                                </Tooltip>
                              );
                            })}
                          </div>
                          {missing.length > 0 && <p className="mt-1 text-[11px] text-destructive">Missing: {missing.map((m) => CONTROLS.find((c) => c.key === m)?.short).join(", ")}</p>}
                          </>}
                        </TableCell>
                        <TableCell className={cn("text-right font-semibold tabular", !device ? "text-muted-foreground" : score < 50 ? "text-destructive" : score < 75 ? "text-warning-ink" : "text-success-ink")}>{device ? score : "—"}</TableCell>
                        <TableCell>{canEdit ? <CriticalitySelect id={e.id} value={e.criticality} /> : <span className="text-xs capitalize">{e.criticality}</span>}</TableCell>
                        <TableCell className="text-right tabular-nums">
                          {cases > 0 ? <Link href={`/cases?q=${encodeURIComponent(e.hostname)}`} className="font-medium text-destructive hover:underline">{cases}</Link> : <span className="text-muted-foreground">0</span>}
                        </TableCell>
                        <TableCell className={cn("text-xs", stale ? "text-warning-ink" : "text-muted-foreground")}>{e.lastSeenAt ? formatRelative(e.lastSeenAt, data.now) : "never"}</TableCell>
                        {canContain && (
                          <TableCell className="text-right">
                            <IsolationButton id={e.id} isolated={e.isolated} hostname={e.hostname} />
                          </TableCell>
                        )}
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
