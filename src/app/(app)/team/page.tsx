import { Check, Lock, ShieldCheck, Users } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { DOMAIN_LABEL, PERMISSIONS, ROLES, ROLE_ORDER, ROLE_PERMISSIONS, SECURITY_DOMAINS, can, type Permission } from "@/lib/rbac";
import { tenantOptions } from "@/lib/tenants";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { UserDialogButton, UserRowControls } from "@/components/team/user-dialog";

// Permissions grouped by what part of the product they unlock.
const GROUPS: Array<{ label: string; prefix: string[] }> = [
  { label: "Cases & collaboration", prefix: ["dashboard.", "cases.", "reports."] },
  { label: "Response", prefix: ["containment.", "endpoints.", "playbooks."] },
  { label: "Analysis", prefix: ["investigations.", "forensics.", "governance.", "telemetry.", "intel.", "mitre."] },
  { label: "AI agents", prefix: ["ai."] },
  { label: "Platform", prefix: ["integrations.", "tenants.", "users.", "audit."] },
  { label: "Commercial", prefix: ["pricing."] },
];

async function loadTeam() {
  const now = new Date();
  const users = await db.user.findMany({ orderBy: [{ tenantId: { sort: "asc", nulls: "first" } }, { role: "asc" }, { name: "asc" }], include: { tenant: { select: { name: true } } } });
  return { now, users };
}

export default async function TeamPage() {
  const viewer = await pageGuard("users.manage");
  const [{ now, users }, tenants] = await Promise.all([loadTeam(), tenantOptions()]);
  const staff = users.filter((u) => !u.tenantId);
  const locked = users.filter((u) => u.lockedUntil && u.lockedUntil > now).length;
  const permissionKeys = Object.keys(PERMISSIONS) as Permission[];

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="SOC staff" value={staff.filter((u) => u.active).length} icon={Users} />
        <StatTile label="Client portal users" value={users.filter((u) => u.tenantId && u.active).length} icon={Users} />
        <StatTile label="Roles" value={ROLE_ORDER.length} icon={ShieldCheck} />
        <StatTile label="Locked out (failed logins)" value={locked} icon={Lock} tone={locked ? "warning" : "default"} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Queue coverage</CardTitle>
          <CardDescription>Analysts covering each security domain. Analysts with no queue set work every domain.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {SECURITY_DOMAINS.map((d) => {
            const analysts = staff.filter((u) => u.active && can(u, "cases.triage") && (u.domains.length === 0 || u.domains.includes(d)));
            return (
              <div key={d} className={cn("rounded-lg border p-3", analysts.length === 0 && "border-destructive/50 bg-destructive/5")}>
                <p className="text-xs font-medium">{DOMAIN_LABEL[d]}</p>
                <p className="mt-1 text-xl font-semibold tabular">{analysts.length}</p>
                <p className="text-[11px] text-muted-foreground">{analysts.length === 0 ? "No one on this queue" : "analysts"}</p>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="text-base">People</CardTitle>
            <CardDescription>Accounts lock for 15 minutes after five wrong passwords. Deactivating a user ends their access immediately.</CardDescription>
          </div>
          <UserDialogButton tenants={tenants} />
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Client / queues</TableHead>
                  <TableHead>Last sign-in</TableHead>
                  <TableHead className="text-right">Manage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users.map((u) => {
                  const isLocked = u.lockedUntil && u.lockedUntil > now;
                  return (
                    <TableRow key={u.id} className={cn(!u.active && "opacity-60")}>
                      <TableCell>
                        <p className="text-sm font-medium">{u.name ?? u.email}{u.id === viewer.id && <span className="text-muted-foreground"> (you)</span>}</p>
                        <p className="text-[11px] text-muted-foreground">{u.email}{u.title ? ` · ${u.title}` : ""}</p>
                      </TableCell>
                      <TableCell>
                        <Badge variant={ROLES[u.role].client ? "info" : u.role === "ADMIN" ? "default" : "soft"}>{ROLES[u.role].label}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {u.tenant ? u.tenant.name : u.domains.length ? u.domains.map((d) => DOMAIN_LABEL[d]).join(", ") : <span className="text-muted-foreground">All queues</span>}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {u.lastLoginAt ? formatRelative(u.lastLoginAt, now) : "never"}
                        <p className={u.mfaEnabledAt ? "text-[11px] text-success-ink" : "text-[11px] text-muted-foreground"}>{u.mfaEnabledAt ? "two-step on" : "password only"}</p>
                        {isLocked && <Badge variant="warning" className="ml-1"><Lock /> locked</Badge>}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center justify-end gap-1">
                          <UserDialogButton tenants={tenants} initial={{ id: u.id, name: u.name ?? "", email: u.email, role: u.role, tenantId: u.tenantId, domains: u.domains, title: u.title ?? "" }} />
                          <UserRowControls userId={u.id} active={u.active} self={u.id === viewer.id} mfa={!!u.mfaEnabledAt} />
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">What each role can see and do</CardTitle>
          <CardDescription>The permission matrix enforced on every page and every server action. Client roles only ever see their own organization.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[56rem] border-separate border-spacing-0 text-xs">
              <thead>
                <tr>
                  <th className="sticky left-0 z-10 bg-card py-2 pr-3 text-left font-medium text-muted-foreground">Permission</th>
                  {ROLE_ORDER.map((r) => (
                    <th key={r} className="px-1 py-2 text-center align-bottom font-medium">
                      <span className="block w-16 text-[10px] leading-tight [writing-mode:horizontal-tb]">{ROLES[r].label}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {GROUPS.map((g) => {
                  const keys = permissionKeys.filter((k) => g.prefix.some((p) => k.startsWith(p)));
                  return [
                    <tr key={g.label}>
                      <td colSpan={ROLE_ORDER.length + 1} className="border-b bg-muted/40 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{g.label}</td>
                    </tr>,
                    ...keys.map((k) => (
                      <tr key={k} className="hover:bg-accent/30">
                        <td className="sticky left-0 z-10 border-b bg-card py-1.5 pr-3" title={k}>{PERMISSIONS[k]}</td>
                        {ROLE_ORDER.map((r) => (
                          <td key={r} className="border-b text-center">
                            {ROLE_PERMISSIONS[r].includes(k) ? <Check className="mx-auto size-3.5 text-success-ink" aria-label="allowed" /> : <span className="text-muted-foreground/40" aria-label="not allowed">·</span>}
                          </td>
                        ))}
                      </tr>
                    )),
                  ];
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
