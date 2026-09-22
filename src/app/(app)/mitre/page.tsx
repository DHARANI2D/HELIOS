import { getMitreCoverage } from "@/lib/mitre/coverage";
import { CoverageChart } from "@/components/mitre/coverage-chart";
import { StatTile } from "@/components/dashboard/stat-tile";
import { Crosshair, Target, Layers } from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default async function MitrePage() {
  const tactics = await getMitreCoverage();
  const tacticsWithCoverage = tactics.filter((t) => t.caseCount > 0);
  const totalTechniques = tactics.reduce((sum, t) => sum + t.techniqueCount, 0);
  const totalCaseLinks = tactics.reduce((sum, t) => sum + t.caseCount, 0);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile
          label="Tactics with coverage"
          value={`${tacticsWithCoverage.length} / ${tactics.length}`}
          icon={Layers}
        />
        <StatTile label="Distinct techniques observed" value={totalTechniques} icon={Target} />
        <StatTile label="Case-technique links" value={totalCaseLinks} icon={Crosshair} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cases by MITRE tactic</CardTitle>
          <CardDescription>
            Aggregated across Agent Governance, Investigations, Email &amp;
            File Forensics, and Cases &amp; Alerts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CoverageChart tactics={tactics} />
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {tacticsWithCoverage.map((tactic) => (
          <Card key={tactic.id}>
            <CardHeader>
              <CardTitle className="text-sm">{tactic.name}</CardTitle>
              <CardDescription>{tactic.id}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1.5">
              {tactic.techniques
                .sort((a, b) => b.caseCount - a.caseCount)
                .map((t) => (
                  <Badge key={t.id} variant="outline" className="gap-1">
                    {t.id}
                    <span className="text-muted-foreground">×{t.caseCount}</span>
                  </Badge>
                ))}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
