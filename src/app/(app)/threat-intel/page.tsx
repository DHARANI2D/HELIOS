import { LookupForm } from "@/components/threat-intel/lookup-form";
import { IndicatorTable } from "@/components/threat-intel/indicator-table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function ThreatIntelPage() {
  return (
    <div className="flex flex-col gap-6">
      <LookupForm />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Cached indicators</CardTitle>
          <CardDescription>
            Shared 24h cache — the same lookups back Investigations, Forensics,
            and Cases &amp; Alerts instead of each module querying providers on
            its own.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <IndicatorTable />
        </CardContent>
      </Card>
    </div>
  );
}
