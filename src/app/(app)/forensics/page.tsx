import { Mail, ShieldAlert, TriangleAlert } from "lucide-react";

import { db } from "@/lib/db";
import { StatTile } from "@/components/dashboard/stat-tile";
import { UploadPanel } from "@/components/forensics/upload-panel";
import { EmailCaseTable } from "@/components/forensics/email-case-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

async function getForensicsStats() {
  const [total, malicious, suspicious] = await Promise.all([
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS" } }),
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS", verdict: "malicious" } }),
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS", verdict: "suspicious" } }),
  ]);
  return { total, malicious, suspicious };
}

export default async function ForensicsPage() {
  const stats = await getForensicsStats();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Emails analyzed" value={stats.total} icon={Mail} />
        <StatTile
          label="Malicious"
          value={stats.malicious}
          icon={ShieldAlert}
          tone={stats.malicious > 0 ? "critical" : "default"}
        />
        <StatTile
          label="Suspicious"
          value={stats.suspicious}
          icon={TriangleAlert}
          tone={stats.suspicious > 0 ? "warning" : "default"}
        />
      </div>

      <UploadPanel />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Analyzed emails</CardTitle>
          <CardDescription>
            Click a row for header, body, and attachment forensics — detonate any extracted URL in the sandbox
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EmailCaseTable />
        </CardContent>
      </Card>
    </div>
  );
}
