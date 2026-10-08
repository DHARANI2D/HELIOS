import { Mail, ShieldAlert, TriangleAlert } from "lucide-react";

import { db } from "@/lib/db";
import { requireSession, tenantWhere, type TenantContext } from "@/lib/tenant";
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

async function getForensicsStats(ctx: TenantContext) {
  const scope = tenantWhere(ctx);
  const [total, malicious, suspicious] = await Promise.all([
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS", ...scope } }),
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS", verdict: "malicious", ...scope } }),
    db.case.count({ where: { sourceType: "EMAIL_ANALYSIS", verdict: "suspicious", ...scope } }),
  ]);
  return { total, malicious, suspicious };
}

export default async function ForensicsPage() {
  const ctx = await requireSession();
  const stats = await getForensicsStats(ctx);

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
