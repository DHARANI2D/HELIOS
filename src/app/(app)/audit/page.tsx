import { ScrollText } from "lucide-react";

import { db } from "@/lib/db";
import { StatTile } from "@/components/dashboard/stat-tile";
import { VerifyIntegrityButton } from "@/components/audit/verify-integrity-button";
import { AuditLogTable } from "@/components/audit/audit-log-table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default async function AuditPage() {
  const total = await db.auditLog.count();

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 sm:grid-cols-3">
        <StatTile label="Audit entries" value={total} icon={ScrollText} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Hash-chained audit trail</CardTitle>
          <CardDescription>
            One SHA-256 hash-chained log for every write action across all
            four modules — each entry&apos;s hash depends on the previous
            entry&apos;s, so any tampering breaks the chain
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <VerifyIntegrityButton />
          <AuditLogTable />
        </CardContent>
      </Card>
    </div>
  );
}
