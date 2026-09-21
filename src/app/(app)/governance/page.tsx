import { UserCog, ShieldCheck, ShieldX, Gauge } from "lucide-react";

import { db } from "@/lib/db";
import { StatTile } from "@/components/dashboard/stat-tile";
import { IdentityForm } from "@/components/governance/identity-form";
import { AgentGrid } from "@/components/governance/agent-grid";
import { ScenarioRunner } from "@/components/governance/scenario-runner";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

async function getGovernanceStats() {
  const [total, active, revoked, avgTrustResult] = await Promise.all([
    db.agent.count(),
    db.agent.count({ where: { status: "ACTIVE" } }),
    db.agent.count({ where: { status: "REVOKED" } }),
    db.agent.aggregate({ _avg: { trust: true } }),
  ]);

  return {
    total,
    active,
    revoked,
    avgTrust: Math.round(avgTrustResult._avg.trust ?? 100),
  };
}

export default async function GovernancePage() {
  const stats = await getGovernanceStats();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Total agents" value={stats.total} icon={UserCog} />
        <StatTile label="Active" value={stats.active} icon={ShieldCheck} />
        <StatTile
          label="Revoked"
          value={stats.revoked}
          icon={ShieldX}
          tone={stats.revoked > 0 ? "critical" : "default"}
        />
        <StatTile label="Average trust" value={`${stats.avgTrust}%`} icon={Gauge} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <IdentityForm />
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Workload nodes</CardTitle>
            <CardDescription>
              Click a revoked agent to open its breach investigation
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AgentGrid />
          </CardContent>
        </Card>
      </div>

      <ScenarioRunner />
    </div>
  );
}
