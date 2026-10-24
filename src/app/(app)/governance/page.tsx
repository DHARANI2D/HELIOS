import { headers } from "next/headers";
import Link from "next/link";
import { UserCog, ShieldCheck, ShieldX, Gauge, Activity } from "lucide-react";

import { db } from "@/lib/db";
import { pageGuard } from "@/lib/session";
import { tenantScope } from "@/lib/access";
import { formatRelative } from "@/lib/format";
import { StatTile } from "@/components/dashboard/stat-tile";
import { IdentityForm } from "@/components/governance/identity-form";
import { AgentGrid } from "@/components/governance/agent-grid";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/empty-state";

const DECISION_VARIANT = { allow: "success", deny: "destructive", escalate: "warning" } as const;

async function origin() {
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host") ?? "localhost:3000";
  const proto = h.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  return `${proto}://${host}`;
}

async function loadGovernance(scope: { tenantId?: string | null }) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const decisions = { ...scope, platform: "helios-governance" };
  const [total, active, revoked, avgTrust, last24h, recent] = await Promise.all([
    db.agent.count({ where: scope }),
    db.agent.count({ where: { ...scope, status: "ACTIVE" } }),
    db.agent.count({ where: { ...scope, status: "REVOKED" } }),
    db.agent.aggregate({ where: scope, _avg: { trust: true } }),
    db.securityEvent.groupBy({ by: ["eventType"], where: { ...decisions, timestamp: { gte: since } }, _count: { _all: true } }),
    db.securityEvent.findMany({ where: decisions, orderBy: { timestamp: "desc" }, take: 25 }),
  ]);
  return { total, active, revoked, avgTrust: avgTrust._avg.trust, last24h, recent };
}

export default async function GovernancePage() {
  const user = await pageGuard("governance.manage");
  const [g, base] = await Promise.all([loadGovernance(await tenantScope(user)), origin()]);
  const now = new Date();
  const count = (type: string) => g.last24h.find((d) => d.eventType === type)?._count._all ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatTile label="Governed agents" value={g.total} icon={UserCog} />
        <StatTile label="Active" value={g.active} icon={ShieldCheck} />
        <StatTile label="Revoked" value={g.revoked} icon={ShieldX} tone={g.revoked > 0 ? "critical" : "default"} />
        <StatTile label="Average trust" value={g.avgTrust == null ? "—" : `${Math.round(g.avgTrust)}%`} icon={Gauge} />
        <StatTile label="Decisions (24h)" value={count("agent.allow") + count("agent.deny") + count("agent.escalate")} hint={`${count("agent.deny")} denied · ${count("agent.escalate")} escalated`} icon={Activity} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <IdentityForm origin={base} />
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Agents</CardTitle>
            <CardDescription>Trust recovers with good behaviour and drops on every denial; a constitution breach revokes the agent. Click a revoked agent for its investigation.</CardDescription>
          </CardHeader>
          <CardContent>
            <AgentGrid origin={base} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Recent decisions</CardTitle>
          <CardDescription>Every action your governed agents asked to take, and what the gate decided.</CardDescription>
        </CardHeader>
        <CardContent>
          {g.recent.length === 0 ? (
            <EmptyState icon={Activity} title="No decisions yet" description="Decisions appear here once an agent calls the governance endpoint with its token." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>Agent</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Decision</TableHead>
                    <TableHead>Why</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {g.recent.map((e) => {
                    const meta = (e.metadata ?? {}) as { layer?: string; reason?: string; environment?: string };
                    const decision = e.eventType.replace("agent.", "") as keyof typeof DECISION_VARIANT;
                    return (
                      <TableRow key={e.id}>
                        <TableCell className="text-xs text-muted-foreground">{formatRelative(e.timestamp, now)}</TableCell>
                        <TableCell className="text-sm">{e.userName}</TableCell>
                        <TableCell className="font-mono text-xs">{e.service}<span className="block text-[10px] text-muted-foreground">{meta.environment}</span></TableCell>
                        <TableCell><Badge variant={DECISION_VARIANT[decision] ?? "outline"}>{decision}</Badge></TableCell>
                        <TableCell className="max-w-md text-xs">
                          <span className="text-muted-foreground">{meta.layer?.toLowerCase()}: </span>{meta.reason}
                          {e.caseId && <Link href={`/cases/${e.caseId}`} className="ml-1 text-primary hover:underline">case</Link>}
                        </TableCell>
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
