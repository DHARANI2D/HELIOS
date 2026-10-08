import { Receipt } from "lucide-react";

import { requireSession, requirePlatformRole } from "@/lib/tenant";
import { listInvoices } from "@/lib/billing/service";
import { StatTile } from "@/components/dashboard/stat-tile";
import { InvoicesTable } from "@/components/admin/invoices-table";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default async function PlatformBillingPage() {
  const ctx = await requireSession();
  requirePlatformRole(ctx);

  const invoices = await listInvoices();
  const outstanding = invoices.filter((i) => i.status === "SENT" || i.status === "OVERDUE");

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatTile label="Invoices" value={invoices.length} icon={Receipt} />
        <StatTile
          label="Outstanding"
          value={outstanding.length}
          icon={Receipt}
          tone={outstanding.length > 0 ? "warning" : "default"}
        />
        <StatTile label="Paid" value={invoices.filter((i) => i.status === "PAID").length} icon={Receipt} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Invoices across every tenant</CardTitle>
          <CardDescription>
            No live payment processor is wired up yet — mark invoices paid manually once payment
            arrives (a Stripe webhook would do this automatically in a later pass)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <InvoicesTable initialData={invoices} />
        </CardContent>
      </Card>
    </div>
  );
}
