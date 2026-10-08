import { ShieldAlert, Siren, Radar, Activity } from "lucide-react";

import { db } from "@/lib/db";
import { requireSession, tenantWhere, type TenantContext } from "@/lib/tenant";
import { StatTile } from "@/components/dashboard/stat-tile";
import { SimulatePanel } from "@/components/cases/simulate-panel";
import { CaseTable } from "@/components/cases/case-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

async function getCaseStats(ctx: TenantContext) {
  const scope = tenantWhere(ctx);
  const [total, open, critical, eventCount] = await Promise.all([
    db.case.count({ where: { sourceType: "SIEM_ALERT", ...scope } }),
    db.case.count({ where: { sourceType: "SIEM_ALERT", status: "OPEN", ...scope } }),
    db.case.count({ where: { sourceType: "SIEM_ALERT", severity: "CRITICAL", ...scope } }),
    db.ingestedEvent.count({ where: scope }),
  ]);
  return { total, open, critical, eventCount };
}

export default async function CasesPage() {
  const ctx = await requireSession();
  const stats = await getCaseStats(ctx);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Total alerts" value={stats.total} icon={ShieldAlert} />
        <StatTile label="Open" value={stats.open} icon={Radar} />
        <StatTile
          label="Critical"
          value={stats.critical}
          icon={Siren}
          tone={stats.critical > 0 ? "critical" : "default"}
        />
        <StatTile label="Events ingested" value={stats.eventCount} icon={Activity} />
      </div>

      <SimulatePanel />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Alerts</CardTitle>
          <CardDescription>Click a row to see its detections and timeline</CardDescription>
        </CardHeader>
        <CardContent>
          <CaseTable />
        </CardContent>
      </Card>
    </div>
  );
}
