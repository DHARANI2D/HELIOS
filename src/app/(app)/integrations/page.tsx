import { headers } from "next/headers";
import { CircleCheck, CircleDashed, Plug, TriangleAlert } from "lucide-react";
import type { IntegrationStatus } from "@prisma/client";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { can, roleLabel } from "@/lib/rbac";
import { selectedTenantId, tenantScope } from "@/lib/access";
import { tenantOptions } from "@/lib/tenants";
import { CATEGORIES } from "@/lib/integrations/catalog";
import { listCatalogTools } from "@/lib/integrations/tools";
import { visibleIntegrationsWhere } from "@/lib/integrations/service";
import type { IntegrationConfig } from "@/lib/integrations/dispatch";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { TestBadge } from "@/components/shared/test-badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";
import { OnboardWizard } from "@/components/integrations/onboard-wizard";
import { IntegrationControls } from "@/components/integrations/integration-controls";

const STATUS_VARIANT: Record<IntegrationStatus, "success" | "warning" | "outline" | "destructive"> = {
  CONNECTED: "success",
  DEGRADED: "warning",
  PENDING: "outline",
  DISCONNECTED: "destructive",
};

async function origin() {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  return `${proto}://${host}`;
}

export default async function IntegrationsPage() {
  const user = await pageGuard("integrations.view");
  const canManage = can(user, "integrations.manage");
  const scope = await tenantScope(user);
  const now = new Date();
  const [integrations, tenants, defaultTenantId, staff, base, catalog] = await Promise.all([
    db.integration.findMany({
      where: { AND: [visibleIntegrationsWhere(user), scope] },
      orderBy: [{ tenantId: "asc" }, { category: "asc" }, { createdAt: "asc" }],
      include: { tenant: { select: { name: true, isTest: true } }, assignments: { include: { user: { select: { id: true, name: true, email: true } } } } },
    }),
    tenantOptions(),
    selectedTenantId(user),
    user.isClient ? Promise.resolve([]) : db.user.findMany({ where: { active: true, tenantId: null }, select: { id: true, name: true, email: true, role: true }, orderBy: { name: "asc" } }),
    origin(),
    listCatalogTools({ includeInactive: true }),
  ]);
  const toolByKey = new Map(catalog.map((t) => [t.key, t]));
  const team = staff.map((u) => ({ id: u.id, name: u.name ?? u.email, role: roleLabel(u.role) }));

  const connected = integrations.filter((i) => i.status === "CONNECTED" && i.enabled).length;
  const degraded = integrations.filter((i) => i.status === "DEGRADED").length;
  const pending = integrations.filter((i) => i.status === "PENDING").length;
  const covered = new Set(integrations.filter((i) => i.enabled).map((i) => i.category));
  const pricedCategories = CATEGORIES.filter((c) => c.priced);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Tools onboarded" value={integrations.length} icon={Plug} />
        <StatTile label="Connected" value={connected} icon={CircleCheck} />
        <StatTile label="Degraded" value={degraded} icon={TriangleAlert} tone={degraded > 0 ? "warning" : "default"} />
        <StatTile label="Waiting for first event" value={pending} icon={CircleDashed} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Protection stack coverage</CardTitle>
          <CardDescription>Which security layers have a tool onboarded{scope.tenantId ? " for this client" : " across your clients"}. Gaps are where an attack can go unseen.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {pricedCategories.map((c) => {
            const on = covered.has(c.key);
            return (
              <div key={c.key} className={cn("rounded-lg border p-3", on ? "border-success/40 bg-success/5" : "border-dashed")}>
                <div className="flex items-center gap-1.5">
                  {on ? <CircleCheck className="size-3.5 text-success-ink" /> : <CircleDashed className="size-3.5 text-muted-foreground" />}
                  <p className="text-xs font-medium">{c.label}</p>
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">{on ? `${integrations.filter((i) => i.category === c.key).length} tool(s)` : "Not covered"}</p>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Onboard a tool</CardTitle>
            <CardDescription>
              Pick the client&apos;s tool, decide which roles and people work with it, and get an ingest URL. Vendor alerts become cases; raw telemetry runs through HELIOS detection;
              hosts it reports appear in Endpoints with this tool&apos;s protection controls.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <OnboardWizard
              origin={base}
              isClient={user.isClient}
              tenants={tenants}
              defaultTenantId={user.isClient ? user.tenantId : defaultTenantId}
              team={team}
              categories={CATEGORIES.map((c) => ({ key: c.key, label: c.label, description: c.description, defaultRoles: c.defaultRoles }))}
              tools={catalog.filter((t) => t.active).map((t) => ({ key: t.key, name: t.name, vendor: t.vendor, category: t.category, description: t.description, controls: t.controls, actions: t.actions, ingest: !!t.ingest, offlineCapable: t.offlineCapable, platforms: t.platforms }))}
            />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{user.isClient ? "Your tools" : "Onboarded tools"}</CardTitle>
          <CardDescription>
            {user.isClient || user.role === "ADMIN" || user.role === "SOC_MANAGER"
              ? "Every tool in scope."
              : `Tools your role (${roleLabel(user.role)}) or you personally have been given access to.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {integrations.length === 0 ? (
            <EmptyState icon={Plug} title="No tools yet" description={canManage ? "Onboard the client's EDR, identity provider or email gateway above." : "Ask a SOC manager to onboard a tool or grant your role access."} />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tool</TableHead>
                    {!user.isClient && <TableHead>Client</TableHead>}
                    <TableHead>Status</TableHead>
                    <TableHead>Last data</TableHead>
                    <TableHead>Access</TableHead>
                    <TableHead>Response</TableHead>
                    {canManage && <TableHead className="text-right">Manage</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {integrations.map((i) => {
                    const tool = toolByKey.get(i.vendor);
                    const config = (i.config ?? {}) as IntegrationConfig;
                    return (
                      <TableRow key={i.id}>
                        <TableCell>
                          <p className="text-sm font-medium">{i.name}</p>
                          <p className="text-[11px] text-muted-foreground">{CATEGORIES.find((c) => c.key === i.category)?.label}{i.tokenPrefix ? ` · token ${i.tokenPrefix}` : ""}</p>
                        </TableCell>
                        {!user.isClient && <TableCell className="text-xs">{i.tenant?.name ?? <span className="text-muted-foreground">SOC-wide</span>}{i.tenant?.isTest && <TestBadge className="ml-1.5" />}</TableCell>}
                        <TableCell>
                          <Badge variant={i.enabled ? STATUS_VARIANT[i.status] : "outline"}>{i.enabled ? i.status.toLowerCase() : "disabled"}</Badge>
                          {i.lastError && <p className="mt-0.5 max-w-48 truncate text-[11px] text-destructive" title={i.lastError}>{i.lastError}</p>}
                        </TableCell>
                        <TableCell className="text-xs">
                          {i.lastEventAt ? formatRelative(i.lastEventAt, now) : "—"}
                          <p className="text-[11px] text-muted-foreground">{i.eventCount.toLocaleString()} records</p>
                        </TableCell>
                        <TableCell className="max-w-56 text-xs">
                          <p className="line-clamp-2">{i.allowedRoles.map((r) => roleLabel(r)).join(", ") || "—"}</p>
                          {i.assignments.length > 0 && <p className="text-[11px] text-muted-foreground">+ {i.assignments.map((a) => a.user.name ?? a.user.email).join(", ")}</p>}
                        </TableCell>
                        <TableCell className="text-xs">
                          {tool?.actions.length ? (config.responseWebhookUrl ? <Badge variant="success">connector set</Badge> : <Badge variant="soft">by hand</Badge>) : "—"}
                        </TableCell>
                        {canManage && (
                          <TableCell>
                            <IntegrationControls
                              id={i.id}
                              name={i.name}
                              enabled={i.enabled}
                              pushes={!!tool?.ingest}
                              hasActions={!!tool?.actions.length && i.category !== "chatops"}
                              allowedRoles={i.allowedRoles}
                              assignedUserIds={i.assignments.map((a) => a.userId)}
                              responseWebhookUrl={config.responseWebhookUrl ?? ""}
                              team={team}
                              origin={base}
                              isClient={user.isClient}
                            />
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
