import { Search, CheckCircle2, Loader2, Percent } from "lucide-react";

import { db } from "@/lib/db";
import { StatTile } from "@/components/dashboard/stat-tile";
import { NewInvestigationForm } from "@/components/investigations/new-investigation-form";
import { InvestigationTable } from "@/components/investigations/investigation-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

async function getInvestigationStats() {
  const [total, resolved, investigating, confidenceAgg] = await Promise.all([
    db.case.count({ where: { sourceType: "SOC_INVESTIGATION" } }),
    db.case.count({ where: { sourceType: "SOC_INVESTIGATION", status: "RESOLVED" } }),
    db.case.count({ where: { sourceType: "SOC_INVESTIGATION", status: "INVESTIGATING" } }),
    db.case.aggregate({
      where: { sourceType: "SOC_INVESTIGATION" },
      _avg: { confidence: true },
    }),
  ]);
  return {
    total,
    resolved,
    investigating,
    avgConfidence: Math.round((confidenceAgg._avg.confidence ?? 0) * 100),
  };
}

export default async function InvestigationsPage() {
  const stats = await getInvestigationStats();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Total investigations" value={stats.total} icon={Search} />
        <StatTile label="QA-validated" value={stats.resolved} icon={CheckCircle2} />
        <StatTile label="Still investigating" value={stats.investigating} icon={Loader2} />
        <StatTile label="Avg. RCA confidence" value={`${stats.avgConfidence}%`} icon={Percent} />
      </div>

      <NewInvestigationForm />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Investigations</CardTitle>
          <CardDescription>
            Click a row for the root-cause narrative, entity graph, QA validation, and full report
          </CardDescription>
        </CardHeader>
        <CardContent>
          <InvestigationTable />
        </CardContent>
      </Card>
    </div>
  );
}
