import { ShieldAlert, Siren, Radar, Activity } from "lucide-react";

import { db } from "@/lib/db";
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

async function getCaseStats() {
  const [total, open, critical, eventCount] = await Promise.all([
    db.case.count({ where: { sourceType: "SIEM_ALERT" } }),
    db.case.count({ where: { sourceType: "SIEM_ALERT", status: "OPEN" } }),
    db.case.count({ where: { sourceType: "SIEM_ALERT", severity: "CRITICAL" } }),
    db.ingestedEvent.count(),
  ]);
  return { total, open, critical, eventCount };
}

export default async function CasesPage() {
  const stats = await getCaseStats();

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
